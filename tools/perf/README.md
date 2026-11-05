# Present measurements

`Measure-RosetunPresents.ps1` records how the Rosetun window reaches the
screen while it is dragged: how many frames it presents, through which
present mode (Composed: Flip, Hardware: Independent Flip, Composed: Copy…)
and how often the mode switches. A window that only moves should present
almost nothing.

## PresentMon

Download the console build (`PresentMon-<version>-x64.exe`) from the
releases of <https://github.com/GameTechDev/PresentMon>. The script does not
download it; pass its path. PresentMon reads ETW events: run the script from
an elevated PowerShell 7, or add your account to the "Performance Log Users"
group and sign in again.

## Run

Start Rosetun and show its window, then from the repository root:

```powershell
pwsh -File tools/perf/Measure-RosetunPresents.ps1 -PresentMon C:\Tools\PresentMon.exe -Seconds 15 -Label after
```

After a 3 s countdown (`-CountdownSeconds`), drag the window by its header
for 15 s: fast, with abrupt stops. The CSV goes to `target/perf/`
(`presents-<label>-<time>.csv`) and the summary prints:

- presents in total and per second;
- each present mode with its share, and the switches between modes with their moments;
- the median and the 99th percentile of the time between presents;
- presents that never reached the screen (`MsUntilDisplayed = NA`);
- gaps between presents longer than two refreshes of the monitor
  (`-MonitorHz`, default 100; 300 for a 300 Hz monitor).

Each list shows its first 20 moments, in UTC like the GUI log (a CSV written
before this option has only the time since the start of the run).
Compare them with the `window frame summary` lines in the GUI log, written at
most every 10 s while something happens: swap chain configures, size, DPI and
monitor changes, surface errors by kind, skipped frames, and how long a size
change or an input took to the end of its present.

The log's `graphics surface configuration` line names how many frames the swap
chain may queue.

To print the summary of a CSV again, for example to compare two builds:

```powershell
pwsh -File tools/perf/Measure-RosetunPresents.ps1 -CsvPath target/perf/presents-before-20261104-120000.csv -Seconds 15
```

`-ProcessName` measures another executable (default `rosetun-gui.exe`).
