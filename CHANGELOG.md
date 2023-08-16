Version v1.1.0
---------------------

* Started versioning and CHANGELOG
* Added link to NDSS'22 experiment directory
* Fix bug where snapshot restoration happens after snapshoting, which is not expected
* Created `MachineInitParams` to allow for easier library usage of FirmWire. This enabled better CI testing

## Shannon
* Added hello world module
* Added support for early SM-G930F images and improved DSP sync word resolution for these
* Extended and improve patterns
* Modified `set_event` GLINK command to allow for specific event flags
* S337AP: added hack to bypass SHM initialization failure

## MTK
* Released MTK modules from the original paper
* Modified LTE RRC module to use standard MTK memory allocator instead of PRBM
* Loader: Added warning when NV data is empty
* Disable `AFL_FAST_EXIT` during --fuzz-triage
* FSD: added CREATEDIR command
* FSD: return error on stub RESTORE command
