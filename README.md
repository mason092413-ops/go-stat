Too lazy to read or click system monitor? Here, pops it all out for you at speed.


Probes everything ranging from CPU to Wifi Chip, all whilest needing no root.

Looks into /sys and /proc to track sensors, average loads, memory usage, so on so fourth.



This was partially written with Claude assistance, it is not all coded by an AI however.


**Dependancies**:
Go-lang
Any Linux distro *does not work on windows, as explained here. `if runtime.GOOS != "linux" {
		fmt.Fprintln(os.Stderr, "hwprobe only works with the linux kernel, sorry. ): (it reads /proc and /sys)")
		os.Exit(1)
	}
`*
