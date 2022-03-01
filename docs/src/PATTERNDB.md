# PatternDB

PatternDB is a convienent way to define memory patterns which FirmWire uses to scan the binary baseband firmware during load-time.
You you can think about FirmWire memory patterns as binary regexes tailored towards firmware analysis tasks.
Once a pattern is found, FirmWire associates a symbol to the according pattern (in the simplest case), and, optionally executes lookup and post-lookup functions.
The pattern itself are defined in the `pattern.py`-file present in the different vendor plugins.

PatternDB is used at various places inside FirmWire: For finding MPU-tables during load-time, automatically resolving logging functions, or exporting symbols to the [Modkit](MODKIT.md), to just provide a few examples.
At the time of FirmWire's public release, we provide 18 patterns for Shannon-based modems and 9 for MediaTek-based modems, tested on a variety of firmware images.

## Pattern Syntax

In our paper, we formally defined the syntax for our pattern as follows:

```
Pattern := {
  name := string
  pattern := [ PatternSyntax... ]
  lookup := PatternFn?
  post_lookup := PatternFn?
  required := bool?
  for := [ string... ]?
  within := [ AddressSet... ]?
  offset := integer?
  offset_end := integer?
  align := integer?
}

PatternSyntax :=
r"([a-fA-F0-9]{2}|([?][?+*]))+"
PatternFn := code
AddressSet := SymbolName | AddressRange
SymbolName := string
AddressRange := [integer, integer]

```

But what does this actually mean? Let's consider the following pattern taken from Shannon's `pattern.py`:

```python
   "boot_setup_memory" : {
        "pattern" : [
            "00008004 200c0000",
            "00000004 ????0100", 
        ],
        "offset" : -0x14,
        "align": 4,
        "post_lookup" : handlers.parse_memory_table,
        "required" : True,
    },
```

Here, we define two patterns which are used to create the PatternDB symbol `boot_setup_memory`, using hexadecimal notation of the searched bytes in little-endian encoding.
Note that the second pattern includes `??` symbols - these are basically wildcards, and allows us to match against arbitrary bytes.
Wildcard bytes specified with `??` allow for modifiers as known from regular regexes (pun intended!).
`?+` requires the presence of one or more wildcard bytes, while `?*` allows for zero or more wildcard bytes at the given location to result into a match.

Going back to our example pattern, the actual address associated with the `boot_setup_memory` symbol will be 0x14 _before_ the location of the found pattern, as specified by the `offset` parameter.
`Alignement` defines that the search granularity should be 4-bytes aligned and `required` will cause FirmWire to exit immediately in case this pattern is not found, as it is crucial for the generation of the emulation environment. 
Lastly, the post_lookup function takes a reference to a python function to be executed after the lookup completed. The function signature for this specific postlookup function is as follows:

```python
def parse_memory_table(self, sym, data, offset): 
```
Here, `self` is a reference to the ShannonMachine, `sym` a reference to the PatternDB symbol, `data` the memory searched for, and `offset` the start offset for the search considering the _virtual_ location of the `data` block. 
The patternDB symbol `sym`, on the other hand, contains information about address, name, and type of the symbol.

## Pattern KeyWord Details

| Keyword     | Description                                                                                                                                                          |
| ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| name        | The name of the pattern and the resulting symbol (string)                                                                                                            |
| pattern     | One ore more memory patterns which will create the result on match.                                                                                                  |
| lookup      | Function to use instead of pattern. Parameters are the data block to be searched and the offset to start. Expected to return `None` or integer denoting the address. |
| post_lookup | Function to be executed after successful match. Parameters are described in example above. Expected to return `True` on success, else `False`.                       |
| required    | When set to `True`, FirmWire will not continue execution when no match is found.                                                                                     |
| for         | Specify SoC version in case the symbol shall only be looked up for certain SoC versions.                                                                             |
| within      | On an image with existing symbols, specify in which function to look for this pattern.                                                                               |
| offset      | Offset between matched pattern and address of created symbol.                                                                                                        |
| offset_end  | Same as offset, but caluclate from the end of matched pattern, rather than from the start.                                                                           |
| align       | Memory aligment required for found matches.                                                                                                                          |

## Defining your own Pattern

You want to define your own pattern? Great!
Just extend the `pattern.py` file in the corresponding vendor plugin to include your pattern, and it should be automatically scanned for during the next start of FirmWire.