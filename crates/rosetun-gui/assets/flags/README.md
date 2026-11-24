# Country flags

`flags.png` contains the 4:3 flag artwork from [flag-icons v7.6.0](https://github.com/lipis/flag-icons/tree/v7.6.0/flags/4x3), under the [MIT license](MIT-flag-icons.txt).

To regenerate the atlas, render the two-letter SVGs from that directory at 64 × 48 pixels with resvg. Omit `xx.svg` so unknown codes use the text badge. Extend each flag's edge pixels by three pixels on each side. Sort the tiles by code, lay them out in 16 columns from left to right, and write their uppercase codes to `codes.txt`, one per line with LF endings. Keep unused cells transparent.
