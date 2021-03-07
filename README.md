# nsrinfo

Retrieve basic information from Firefall's NSR replay files.

## Usage

```
Usage: nsrinfo [OPTION] FILE

Arguments:
 OPTION   An option to influence the application behavior.
 FILE     The NSR file to extract information from.

Possible options:
 --help   Show this text
```

**Note:** There's currently no `OPTION` implemented

## Basic Information

- Header Size: Size of the NSR header in bytes
- Protocol Version: Replay/streaming protocol version
- Zone: Firefall zone id (e.g. 448 for New Eden)
- Description: Description given when recording the replay
- Date: Date of the replay recording
- User: Player name
- Firefall Version: Firefall version
- Date2: Alternative date format of when the replay was recorded

## License

This software is available under 2 licenses -- choose whichever you prefer.
For further details take a look at the LICENSE file.

- Public Domain
- MIT