// gostat - dependancy free, cli probe for averages, meant to be blazing with Go.


// reads inner values, such as /proc and /sys in the file tree, also can run with no root.

// nvidia is supported, but as always on linux AMD is preferable.

// author Mason Nunez, 2026, this program is free under the MIT license. see more at https://opensource.org/license/mit

// flags:  -interval 2s   sampling window
//
// watch         refresh continuously
// (Ctrl-C to quit)
//
//-json
//machine-readable output (one object per line in -watch mode)
//
//    -inventory=false
// skips PCI/USB inventory



package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ---------------------------------------------------------------- data model

type Snapshot struct {
	Time        time.Time
	Hostname    string
	Kernel      string
	Uptime      string
	WindowSecs  float64
	CPU         CPUInfo
	Memory      MemInfo
	Disks       []DiskInfo
	Filesystems []FSInfo
	Network     []NetInfo
	GPUs        []GPUInfo
	Sensors     []Sensor
	Batteries   []Battery
	PCI         []PCIDev
	USB         []USBDev
	// figures out general hardware
}

type CPUInfo struct {
	Model      string
	Logical    int
	UsagePct   float64
	PerCore    []float64
	Load1      float64
	Load5      float64
	Load15     float64
	AvgFreqMHz float64
	// all probes cpu in file tree
}

type MemInfo struct {
	Total, Used, Available, Free, Buffers, Cached uint64
	SwapTotal, SwapUsed                           uint64
}

type DiskInfo struct {
	Name, Model, Kind string
	SizeBytes         uint64
	ReadBps, WriteBps float64
	UtilPct           float64
}

type FSInfo struct {
	Device, Mount, Type string
	Total, Used, Avail  uint64
	UsedPct             float64
}

type WifiInfo struct {
	SSID        string
	FreqMHz     string
	LinkQuality float64
	SignalDBm   float64
	NoiseDBm    float64
	TxBitrate   string
	RxBitrate   string
}

type NetInfo struct {
	Name, State, MAC, Driver string
	SpeedMbps                int64
	Wireless                 bool
	RxBytes, TxBytes         uint64 // lifetime totals
	RxErrors, TxErrors       uint64
	RxDrops, TxDrops         uint64
	RxBps, TxBps             float64 // bytes/s over the sample window
	RxPPS, TxPPS             float64 // packets/s over the sample window
	RxPPSAvg, TxPPSAvg       float64 // packets/s averaged since program start
	Wifi                     *WifiInfo
	// will NOT work without a wifi driver, it can't pick it up with none
}

// Unknown numeric GPU fields are -1.
type GPUInfo struct {
	Index                  int
	Vendor, Name, Driver   string
	Source                 string
	UtilPct, MemUtilPct    float64
	MemUsedMB, MemTotalMB  float64
	TempC, PowerW, ClockMHz float64
}

type Sensor struct {
	Chip, Label string
	Value       float64
	Unit        string
}

type Battery struct {
	Name, Status string
	CapacityPct  int64
}

type PCIDev struct {
	Slot, VendorID, DeviceID, Class, Driver, Desc string
}

type USBDev struct {
	Bus, VendorID, ProductID, Manufacturer, Product, SpeedMbps string
}

// ------------------------------------------------------------------- helpers

func readFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func readInt(path string) (int64, bool) {
	s := readFile(path)
	if s == "" {
		return 0, false
	}
	v, err := strconv.ParseInt(s, 0, 64)
	return v, err == nil
}

// pf parses a float, tolerating the trailing "." used in /proc/net/wireless.
func pf(s string) (float64, bool) {
	s = strings.TrimSuffix(strings.TrimSpace(s), ".")
	v, err := strconv.ParseFloat(s, 64)
	return v, err == nil
}

func pfOr(s string, def float64) float64 {
	if v, ok := pf(s); ok {
		return v
	}
	return def
}

func run(timeout time.Duration, name string, args ...string) (string, error) {
	if _, err := exec.LookPath(name); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	return string(out), err
}

func rate(a, b uint64, dt float64) float64 {
	if b < a || dt <= 0 {
		return 0
	}
	return float64(b-a) / dt
}

func pct(used, total uint64) float64 {
	if total == 0 {
		return 0
	}
	return 100 * float64(used) / float64(total)
}

func hb(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func hr(bps float64) string { return hb(uint64(bps)) + "/s" }

func bar(p float64, width int) string {
	if p < 0 {
		p = 0
	}
	if p > 100 {
		p = 100
	}
	n := int(p/100*float64(width) + 0.5)
	return "[" + strings.Repeat("#", n) + strings.Repeat(".", width-n) + "]"
}

func opt(v float64, format string) string {
	if v < 0 {
		return "n/a"
	}
	return fmt.Sprintf(format, v)
}

// -------------------------------------------------------- raw counter reads

type cpuTimes struct{ idle, total uint64 }
type diskCtr struct{ rSect, wSect, ioMs uint64 }
type netCtr struct{ rxB, rxP, rxE, rxD, txB, txP, txE, txD uint64 }

type counters struct {
	at   time.Time
	cpu  map[string]cpuTimes
	disk map[string]diskCtr
	net  map[string]netCtr
}

func readCounters() counters {
	return counters{
		at:   time.Now(),
		cpu:  readCPUTimes(),
		disk: readDiskCounters(),
		net:  readNetCounters(),
	}
}

func readCPUTimes() map[string]cpuTimes {
	m := map[string]cpuTimes{}
	f, err := os.Open("/proc/stat")
	if err != nil {
		return m
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 8 || !strings.HasPrefix(fields[0], "cpu") {
			continue
		}
		var total, idle uint64
		// user nice system idle iowait irq softirq steal (guest is already in user)
		for i, s := range fields[1:] {
			if i >= 8 {
				break
			}
			v, _ := strconv.ParseUint(s, 10, 64)
			total += v
			if i == 3 || i == 4 {
				idle += v
			}
		}
		m[fields[0]] = cpuTimes{idle, total}
	}
	return m
}

func readDiskCounters() map[string]diskCtr {
	m := map[string]diskCtr{}
	f, err := os.Open("/proc/diskstats")
	if err != nil {
		return m
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 13 {
			continue
		}
		u := func(i int) uint64 { v, _ := strconv.ParseUint(fields[i], 10, 64); return v }
		m[fields[2]] = diskCtr{rSect: u(5), wSect: u(9), ioMs: u(12)}
	}
	return m
}

func readNetCounters() map[string]netCtr {
	m := map[string]netCtr{}
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return m
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		i := strings.Index(line, ":")
		if i < 0 {
			continue
		}
		name := strings.TrimSpace(line[:i])
		fields := strings.Fields(line[i+1:])
		if len(fields) < 12 {
			continue
		}
		u := func(k int) uint64 { v, _ := strconv.ParseUint(fields[k], 10, 64); return v }
		m[name] = netCtr{u(0), u(1), u(2), u(3), u(8), u(9), u(10), u(11)}
	}
	return m
}

// ---------------------------------------------------------------- collectors

func buildSnapshot(prev, cur, first counters) Snapshot {
	dt := cur.at.Sub(prev.at).Seconds()
	if dt <= 0 {
		dt = 1
	}
	s := Snapshot{Time: cur.at, WindowSecs: dt}
	s.Hostname, _ = os.Hostname()
	s.Kernel = readFile("/proc/sys/kernel/osrelease")
	s.Uptime = uptime()
	s.CPU = cpuInfo(prev.cpu, cur.cpu)
	s.Memory = memInfo()
	s.Disks = disks(prev.disk, cur.disk, dt)
	s.Filesystems = filesystems()
	s.Network = networks(prev, cur, first)
	s.GPUs = gpus()
	s.Sensors = sensors()
	s.Batteries = batteries()
	return s
}

func uptime() string {
	f := strings.Fields(readFile("/proc/uptime"))
	if len(f) == 0 {
		return "?"
	}
	secs, _ := pf(f[0])
	d := time.Duration(secs) * time.Second
	return fmt.Sprintf("%dd %02dh %02dm", int(d.Hours())/24, int(d.Hours())%24, int(d.Minutes())%60)
}

func cpuUsage(a, b cpuTimes) float64 {
	if b.total <= a.total {
		return 0
	}
	dt := b.total - a.total
	di := b.idle - a.idle
	if di > dt {
		return 0
	}
	return 100 * float64(dt-di) / float64(dt)
}

func cpuInfo(a, b map[string]cpuTimes) CPUInfo {
	c := CPUInfo{}
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			k, v, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			k = strings.TrimSpace(k)
			switch {
				case k == "processor":
					c.Logical++
				case (k == "model name" || k == "Hardware" || k == "Model") && c.Model == "":
					c.Model = strings.TrimSpace(v)
			}
		}
	}
	c.UsagePct = cpuUsage(a["cpu"], b["cpu"])
	for i := 0; i < c.Logical; i++ {
		name := fmt.Sprintf("cpu%d", i)
		x, ok1 := a[name]
		y, ok2 := b[name]
		if ok1 && ok2 {
			c.PerCore = append(c.PerCore, cpuUsage(x, y))
		}
	}
	la := strings.Fields(readFile("/proc/loadavg"))
	if len(la) >= 3 {
		c.Load1, _ = pf(la[0])
		c.Load5, _ = pf(la[1])
		c.Load15, _ = pf(la[2])
	}
	freqs, _ := filepath.Glob("/sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_cur_freq")
	var sum float64
	var n int
	for _, p := range freqs {
		if khz, ok := readInt(p); ok {
			sum += float64(khz) / 1000
			n++
		}
	}
	if n > 0 {
		c.AvgFreqMHz = sum / float64(n)
	}
	return c
}

func memInfo() MemInfo {
	kv := map[string]uint64{}
	data, _ := os.ReadFile("/proc/meminfo")
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		f := strings.Fields(v)
		if len(f) == 0 {
			continue
		}
		n, _ := strconv.ParseUint(f[0], 10, 64)
		kv[k] = n * 1024 // values are in kB
	}
	m := MemInfo{
		Total:     kv["MemTotal"],
		Available: kv["MemAvailable"],
		Free:      kv["MemFree"],
		Buffers:   kv["Buffers"],
		Cached:    kv["Cached"],
		SwapTotal: kv["SwapTotal"],
	}
	if m.Total > m.Available {
		m.Used = m.Total - m.Available
	}
	if kv["SwapTotal"] > kv["SwapFree"] {
		m.SwapUsed = kv["SwapTotal"] - kv["SwapFree"]
	}
	return m
}

func disks(a, b map[string]diskCtr, dt float64) []DiskInfo {
	entries, _ := os.ReadDir("/sys/block")
	var out []DiskInfo
	for _, e := range entries {
		n := e.Name()
		if strings.HasPrefix(n, "loop") || strings.HasPrefix(n, "ram") || strings.HasPrefix(n, "dm-") {
			continue
		}
		base := "/sys/block/" + n
		sectors, _ := readInt(base + "/size")
		d := DiskInfo{
			Name:      n,
			Model:     readFile(base + "/device/model"),
			SizeBytes: uint64(sectors) * 512,
		}
		rot, _ := readInt(base + "/queue/rotational")
		switch {
			case strings.HasPrefix(n, "nvme"):
				d.Kind = "NVMe"
			case strings.HasPrefix(n, "zram"):
				d.Kind = "zram"
			case rot == 1:
				d.Kind = "HDD"
			default:
				d.Kind = "SSD/flash"
		}
		x, ok1 := a[n]
		y, ok2 := b[n]
		if ok1 && ok2 {
			d.ReadBps = rate(x.rSect, y.rSect, dt) * 512
			d.WriteBps = rate(x.wSect, y.wSect, dt) * 512
			d.UtilPct = rate(x.ioMs, y.ioMs, dt) / 10 // ms busy per second -> %
			if d.UtilPct > 100 {
				d.UtilPct = 100
			}
		}
		if d.SizeBytes > 0 {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func filesystems() []FSInfo {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []FSInfo
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 || !strings.HasPrefix(fields[0], "/dev/") || strings.HasPrefix(fields[0], "/dev/loop") {
			continue
		}
		if seen[fields[0]] {
			continue
		}
		seen[fields[0]] = true
		mp := strings.ReplaceAll(fields[1], "\\040", " ")
		var st syscall.Statfs_t
		if syscall.Statfs(mp, &st) != nil {
			continue
		}
		bs := uint64(st.Bsize)
		total := uint64(st.Blocks) * bs
		free := uint64(st.Bfree) * bs
		avail := uint64(st.Bavail) * bs
		used := uint64(0)
		if total > free {
			used = total - free
		}
		out = append(out, FSInfo{
			Device: fields[0], Mount: mp, Type: fields[2],
			Total: total, Used: used, Avail: avail,
			UsedPct: pct(used, used+avail), // same definition as df
		})
	}
	return out
}

func readWireless() map[string]*WifiInfo {
	m := map[string]*WifiInfo{}
	data, err := os.ReadFile("/proc/net/wireless")
	if err != nil {
		return m
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) < 2 {
		return m
	}
	for _, l := range lines[2:] { // skip the two header lines
		i := strings.Index(l, ":")
		if i < 0 {
			continue
		}
		f := strings.Fields(l[i+1:]) // status, link, level, noise, ...
		if len(f) < 4 {
			continue
		}
		w := &WifiInfo{}
		w.LinkQuality, _ = pf(f[1])
		w.SignalDBm, _ = pf(f[2])
		w.NoiseDBm, _ = pf(f[3])
		m[strings.TrimSpace(l[:i])] = w
	}
	return m
}

func iwLink(name string, w *WifiInfo) {
	out, err := run(2*time.Second, "iw", "dev", name, "link")
	if err != nil {
		return
	}
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		switch {
			case strings.HasPrefix(l, "SSID:"):
				w.SSID = strings.TrimSpace(l[len("SSID:"):])
			case strings.HasPrefix(l, "freq:"):
				w.FreqMHz = strings.TrimSpace(l[len("freq:"):])
			case strings.HasPrefix(l, "tx bitrate:"):
				w.TxBitrate = strings.TrimSpace(l[len("tx bitrate:"):])
			case strings.HasPrefix(l, "rx bitrate:"):
				w.RxBitrate = strings.TrimSpace(l[len("rx bitrate:"):])
			case strings.HasPrefix(l, "signal:") && w.SignalDBm == 0:
				if f := strings.Fields(l[len("signal:"):]); len(f) > 0 {
					w.SignalDBm, _ = pf(f[0])
				}
		}
	}
}

func networks(prev, cur, first counters) []NetInfo {
	dt := cur.at.Sub(prev.at).Seconds()
	elapsed := cur.at.Sub(first.at).Seconds()
	wl := readWireless()
	entries, _ := os.ReadDir("/sys/class/net")
	var out []NetInfo
	for _, e := range entries {
		n := e.Name()
		if n == "lo" {
			continue
		}
		base := "/sys/class/net/" + n
		ni := NetInfo{
			Name:  n,
			State: readFile(base + "/operstate"),
			MAC:   readFile(base + "/address"),
		}
		if sp, ok := readInt(base + "/speed"); ok && sp > 0 {
			ni.SpeedMbps = sp
		}
		if t, err := os.Readlink(base + "/device/driver"); err == nil {
			ni.Driver = filepath.Base(t)
		}
		_, werr := os.Stat(base + "/wireless")
		_, perr := os.Stat(base + "/phy80211")
		ni.Wireless = werr == nil || perr == nil

		c1, ok1 := cur.net[n]
		c0, ok0 := prev.net[n]
		cf := first.net[n]
		if ok1 {
			ni.RxBytes, ni.TxBytes = c1.rxB, c1.txB
			ni.RxErrors, ni.TxErrors = c1.rxE, c1.txE
			ni.RxDrops, ni.TxDrops = c1.rxD, c1.txD
			ni.RxPPSAvg = rate(cf.rxP, c1.rxP, elapsed)
			ni.TxPPSAvg = rate(cf.txP, c1.txP, elapsed)
		}
		if ok1 && ok0 {
			ni.RxBps = rate(c0.rxB, c1.rxB, dt)
			ni.TxBps = rate(c0.txB, c1.txB, dt)
			ni.RxPPS = rate(c0.rxP, c1.rxP, dt)
			ni.TxPPS = rate(c0.txP, c1.txP, dt)
		}
		if ni.Wireless {
			w := wl[n]
			if w == nil {
				w = &WifiInfo{}
			}
			if ni.State == "up" {
				iwLink(n, w)
			}
			ni.Wifi = w
		}
		out = append(out, ni)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ----------------------------------------------------------------------- GPU

func lspciNames() map[string]string {
	m := map[string]string{}
	out, err := run(3*time.Second, "lspci", "-D")
	if err != nil {
		return m
	}
	for _, l := range strings.Split(out, "\n") {
		slot, desc, ok := strings.Cut(l, " ")
		if ok {
			m[slot] = desc
		}
	}
	return m
}

func nvidiaGPUs() []GPUInfo {
	out, err := run(4*time.Second, "nvidia-smi",
			"--query-gpu=name,utilization.gpu,utilization.memory,memory.used,memory.total,temperature.gpu,power.draw,clocks.sm",
		 "--format=csv,noheader,nounits")
	if err != nil {
		return nil
	}
	var gs []GPUInfo
	for i, line := range strings.Split(strings.TrimSpace(out), "\n") {
		p := strings.Split(line, ",")
		if len(p) < 8 {
			continue
		}
		gs = append(gs, GPUInfo{
			Index: i, Vendor: "NVIDIA", Name: strings.TrimSpace(p[0]), Driver: "nvidia", Source: "nvidia-smi",
			    UtilPct: pfOr(p[1], -1), MemUtilPct: pfOr(p[2], -1),
			    MemUsedMB: pfOr(p[3], -1), MemTotalMB: pfOr(p[4], -1),
			    TempC: pfOr(p[5], -1), PowerW: pfOr(p[6], -1), ClockMHz: pfOr(p[7], -1),
		})
	}
	return gs
}

func gpus() []GPUInfo {
	gs := nvidiaGPUs()
	haveNvidia := len(gs) > 0
	names := lspciNames()

	cards, _ := filepath.Glob("/sys/class/drm/card*")
	for _, c := range cards {
		base := filepath.Base(c)
		if strings.Contains(base, "-") { // skip connectors like card0-DP-1
			continue
		}
		dev := filepath.Join(c, "device")
		vendorID := readFile(dev + "/vendor")
		if vendorID == "0x10de" && haveNvidia {
			continue // already reported via nvidia-smi
		}
		g := GPUInfo{
			Index: len(gs), Source: "sysfs " + base,
			UtilPct: -1, MemUtilPct: -1, MemUsedMB: -1, MemTotalMB: -1,
			TempC: -1, PowerW: -1, ClockMHz: -1,
		}
		switch vendorID {
			case "0x10de":
				g.Vendor = "NVIDIA"
			case "0x1002":
				g.Vendor = "AMD"
			case "0x8086":
				g.Vendor = "Intel"
			default:
				g.Vendor = vendorID
		}
		if t, err := os.Readlink(dev + "/driver"); err == nil {
			g.Driver = filepath.Base(t)
		}
		g.Name = readFile(dev + "/product_name")
		if real, err := filepath.EvalSymlinks(dev); err == nil {
			if d := names[filepath.Base(real)]; d != "" && g.Name == "" {
				g.Name = d
			}
		}
		if g.Name == "" {
			g.Name = "device " + readFile(dev+"/device")
		}

		// AMD (amdgpu) exposes live counters in sysfs.
		if v, ok := readInt(dev + "/gpu_busy_percent"); ok {
			g.UtilPct = float64(v)
		}
		if v, ok := readInt(dev + "/mem_info_vram_used"); ok {
			g.MemUsedMB = float64(v) / (1 << 20)
		}
		if v, ok := readInt(dev + "/mem_info_vram_total"); ok {
			g.MemTotalMB = float64(v) / (1 << 20)
			if g.MemUsedMB >= 0 && v > 0 {
				g.MemUtilPct = 100 * g.MemUsedMB * (1 << 20) / float64(v)
			}
		}
		if hw, _ := filepath.Glob(dev + "/hwmon/hwmon*"); len(hw) > 0 {
			if v, ok := readInt(hw[0] + "/temp1_input"); ok {
				g.TempC = float64(v) / 1000
			}
			if v, ok := readInt(hw[0] + "/power1_average"); ok {
				g.PowerW = float64(v) / 1e6
			} else if v, ok := readInt(hw[0] + "/power1_input"); ok {
				g.PowerW = float64(v) / 1e6
			}
			if v, ok := readInt(hw[0] + "/freq1_input"); ok {
				g.ClockMHz = float64(v) / 1e6
			}
		}
		// Intel (i915/xe) exposes the current frequency only.
		for _, p := range []string{c + "/gt_cur_freq_mhz", c + "/gt/gt0/rps_cur_freq_mhz"} {
			if v, ok := readInt(p); ok {
				g.ClockMHz = float64(v)
				break
			}
		}
		gs = append(gs, g)
	}
	return gs
}

// ------------------------------------------------- sensors, battery, devices

func sensors() []Sensor {
	var out []Sensor
	chips, _ := filepath.Glob("/sys/class/hwmon/hwmon*")
	for _, c := range chips {
		chip := readFile(c + "/name")
		temps, _ := filepath.Glob(c + "/temp*_input")
		for _, t := range temps {
			v, ok := readInt(t)
			if !ok {
				continue
			}
			stem := strings.TrimSuffix(filepath.Base(t), "_input")
			label := readFile(c + "/" + stem + "_label")
			if label == "" {
				label = stem
			}
			out = append(out, Sensor{chip, label, float64(v) / 1000, "C"})
		}
		fans, _ := filepath.Glob(c + "/fan*_input")
		for _, f := range fans {
			if v, ok := readInt(f); ok {
				out = append(out, Sensor{chip, strings.TrimSuffix(filepath.Base(f), "_input"), float64(v), "RPM"})
			}
		}
	}
	return out
}

func batteries() []Battery {
	var out []Battery
	ps, _ := filepath.Glob("/sys/class/power_supply/*")
	for _, p := range ps {
		if readFile(p+"/type") != "Battery" {
			continue
		}
		cap, _ := readInt(p + "/capacity")
		out = append(out, Battery{Name: filepath.Base(p), Status: readFile(p + "/status"), CapacityPct: cap})
	}
	return out
}

func pciDevices() []PCIDev {
	names := lspciNames()
	dirs, _ := filepath.Glob("/sys/bus/pci/devices/*")
	var out []PCIDev
	for _, d := range dirs {
		slot := filepath.Base(d)
		p := PCIDev{
			Slot:     slot,
			VendorID: strings.TrimPrefix(readFile(d+"/vendor"), "0x"),
			DeviceID: strings.TrimPrefix(readFile(d+"/device"), "0x"),
			Class:    readFile(d + "/class"),
			Desc:     names[slot],
		}
		if t, err := os.Readlink(d + "/driver"); err == nil {
			p.Driver = filepath.Base(t)
		}
		out = append(out, p)
	}
	return out
}

func usbDevices() []USBDev {
	dirs, _ := filepath.Glob("/sys/bus/usb/devices/*")
	var out []USBDev
	for _, d := range dirs {
		vid := readFile(d + "/idVendor")
		if vid == "" { // interface entries have no idVendor
			continue
		}
		out = append(out, USBDev{
			Bus:          filepath.Base(d),
			     VendorID:     vid,
			     ProductID:    readFile(d + "/idProduct"),
			     Manufacturer: readFile(d + "/manufacturer"),
			     Product:      readFile(d + "/product"),
			     SpeedMbps:    readFile(d + "/speed"),
		})
	}
	return out
}

// ------------------------------------------------------------------ printing

func section(title string) { fmt.Printf("\n--- %s ---\n", title) }

func printSnapshot(s Snapshot, inventory bool) {
	fmt.Printf("%s | kernel %s | up %s | %s | sample window %.1fs\n",
		   s.Hostname, s.Kernel, s.Uptime, s.Time.Format("15:04:05"), s.WindowSecs)

	c := s.CPU
	section("CPU")
	fmt.Printf("%s (%d threads)\n", c.Model, c.Logical)
	fmt.Printf("usage %5.1f%% %s   load %.2f %.2f %.2f", c.UsagePct, bar(c.UsagePct, 20), c.Load1, c.Load5, c.Load15)
	if c.AvgFreqMHz > 0 {
		fmt.Printf("   avg clock %.0f MHz", c.AvgFreqMHz)
	}
	fmt.Println()
	if len(c.PerCore) > 0 {
		fmt.Print("per-core: ")
		for i, p := range c.PerCore {
			fmt.Printf("%d:%.0f%% ", i, p)
		}
		fmt.Println()
	}

	m := s.Memory
	section("Memory")
	fmt.Printf("RAM  %s / %s (%.1f%%) %s\n", hb(m.Used), hb(m.Total), pct(m.Used, m.Total), bar(pct(m.Used, m.Total), 20))
	fmt.Printf("     available %s, free %s, buffers %s, cached %s\n", hb(m.Available), hb(m.Free), hb(m.Buffers), hb(m.Cached))
	if m.SwapTotal > 0 {
		fmt.Printf("swap %s / %s (%.1f%%)\n", hb(m.SwapUsed), hb(m.SwapTotal), pct(m.SwapUsed, m.SwapTotal))
	} else {
		fmt.Println("swap none")
	}

	section("GPU")
	if len(s.GPUs) == 0 {
		fmt.Println("no GPU detected")
	}
	for _, g := range s.GPUs {
		fmt.Printf("#%d %s %s (driver %s, via %s)\n", g.Index, g.Vendor, g.Name, g.Driver, g.Source)
		fmt.Printf("   util %s%%  vram %s / %s MB  temp %s C  power %s W  clock %s MHz\n",
			   opt(g.UtilPct, "%.0f"), opt(g.MemUsedMB, "%.0f"), opt(g.MemTotalMB, "%.0f"),
			   opt(g.TempC, "%.0f"), opt(g.PowerW, "%.1f"), opt(g.ClockMHz, "%.0f"))
	}

	section("Storage devices")
	for _, d := range s.Disks {
		fmt.Printf("%-10s %-9s %9s  %-24s read %-11s write %-11s busy %3.0f%%\n",
			   d.Name, d.Kind, hb(d.SizeBytes), d.Model, hr(d.ReadBps), hr(d.WriteBps), d.UtilPct)
	}
	section("Filesystems")
	for _, f := range s.Filesystems {
		fmt.Printf("%-18s %-22s %-6s %9s / %-9s %5.1f%% %s\n",
			   f.Device, f.Mount, f.Type, hb(f.Used), hb(f.Total), f.UsedPct, bar(f.UsedPct, 15))
	}

	section("Network")
	for _, n := range s.Network {
		kind := "wired/virtual"
		if n.Wireless {
			kind = "wifi"
		}
		speed := ""
		if n.SpeedMbps > 0 {
			speed = fmt.Sprintf(", %d Mb/s", n.SpeedMbps)
		}
		fmt.Printf("%s [%s, %s%s, driver %s, %s]\n", n.Name, kind, n.State, speed, n.Driver, n.MAC)
		fmt.Printf("   rx %-11s %8.1f pkt/s (avg %.1f)   tx %-11s %8.1f pkt/s (avg %.1f)\n",
			   hr(n.RxBps), n.RxPPS, n.RxPPSAvg, hr(n.TxBps), n.TxPPS, n.TxPPSAvg)
		fmt.Printf("   totals rx %s tx %s | errors rx/tx %d/%d | drops rx/tx %d/%d\n",
			   hb(n.RxBytes), hb(n.TxBytes), n.RxErrors, n.TxErrors, n.RxDrops, n.TxDrops)
		if w := n.Wifi; w != nil && n.State == "up" {
			fmt.Printf("   wifi ssid=%q freq=%s MHz signal=%.0f dBm quality=%.0f noise=%.0f dBm tx=%s rx=%s\n",
				   w.SSID, w.FreqMHz, w.SignalDBm, w.LinkQuality, w.NoiseDBm, w.TxBitrate, w.RxBitrate)
		}
	}

	if len(s.Sensors) > 0 {
		section("Sensors")
		for _, x := range s.Sensors {
			fmt.Printf("%-14s %-18s %.1f %s\n", x.Chip, x.Label, x.Value, x.Unit)
		}
	}
	if len(s.Batteries) > 0 {
		section("Battery")
		for _, b := range s.Batteries {
			fmt.Printf("%s: %d%% (%s)\n", b.Name, b.CapacityPct, b.Status)
		}
	}
	if inventory {
		section("PCI devices")
		for _, p := range s.PCI {
			fmt.Printf("%s [%s:%s] %-12s %s\n", p.Slot, p.VendorID, p.DeviceID, p.Driver, p.Desc)
		}
		section("USB devices")
		for _, u := range s.USB {
			fmt.Printf("%-8s %s:%s %s %s (%s Mb/s)\n", u.Bus, u.VendorID, u.ProductID, u.Manufacturer, u.Product, u.SpeedMbps)
		}
	}
}

// ---------------------------------------------------------------------- main

func main() {
	interval := flag.Duration("interval", time.Second, "sampling window used for rates")
	watch := flag.Bool("watch", false, "refresh continuously")
	asJSON := flag.Bool("json", false, "emit JSON instead of text")
	inventory := flag.Bool("inventory", true, "include PCI/USB inventory")
	flag.Parse()

	if runtime.GOOS != "linux" {
		fmt.Fprintln(os.Stderr, "go-stat only works on with the linux kernel, sorry. ): (it reads /proc and /sys)")
		os.Exit(1)
	}

	// The inventory rarely changes, so collect it once.
	var pci []PCIDev
	var usb []USBDev
	if *inventory {
		pci, usb = pciDevices(), usbDevices()
	}

	enc := json.NewEncoder(os.Stdout)
	if !*watch {
		enc.SetIndent("", "  ")
	}

	first := readCounters()
	prev := first
	for {
		time.Sleep(*interval)
		cur := readCounters()
		snap := buildSnapshot(prev, cur, first)
		snap.PCI, snap.USB = pci, usb
		prev = cur

		if *asJSON {
			_ = enc.Encode(snap)
		} else {
			if *watch {
				fmt.Print("\033[H\033[2J") // clear screen
			}
			printSnapshot(snap, *inventory)
		}
		if !*watch {
			return
		}
	}
}
