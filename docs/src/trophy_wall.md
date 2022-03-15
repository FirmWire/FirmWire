# Trophy Wall

FirmWire is intended as tool to find security critical bugs and to ease baseband specific research.
As such, we are happy to showcase how FirmWire is used! On this page, you can find details to vulnerabilties found with FirmWire, talks about the framework, and blogposts describing its usage.


## Vulnerabilities

So far, FirmWire was involved in finding the following vulnerabilities:


| CVE            | Severity       | Finder        | Description                                                                                                                                                                                                                                                                           |
| -------------- | -------------- | ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| CVE-2021-25479 | 7.2 (high)     | Team FirmWire | A possible heap-based buffer overflow vulnerability in Exynos CP Chipset prior to SMR Oct-2021 Release 1 allows arbitrary memory write and code execution.                                                                                                                            |
| CVE-2021-25478 | 7.2 (high)     | Team FirmWire | A possible stack-based buffer overflow vulnerability in Exynos CP Chipset prior to SMR Oct-2021 Release 1 allows arbitrary memory write and code execution.                                                                                                                           |
| CVE-2020-25279 | 9.8 (critical) | Team FirmWire | An issue was discovered on Samsung mobile devices with O(8.x), P(9.0), and Q(10.0) (Exynos chipsets) software. The baseband component has a buffer overflow via an abnormal SETUP message, leading to execution of arbitrary code. The Samsung ID is SVE-2020-18098 (September 2020). |
| CVE-2021-25477 | 4.9 (medium)   | Team FirmWire | An improper error handling in Mediatek RRC Protocol stack prior to SMR Oct-2021 Release 1 allows modem crash and remote denial of service.                                                                                                                                            |

## Talks


| Title                                                                 | Where             | Who                                    | Links                                                                                                                                                                        | Description                                                                                                                                 |
| --------------------------------------------------------------------- | ----------------- | -------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| Emulating Samsung's Baseband for Security Testing                     | Blackhat USA'20   | Team FirmWire (Grant & Marius)         | [youtube](https://www.youtube.com/watch?v=wkWUU8820ro) [slides](http://i.blackhat.com/USA-20/Wednesday/us-20-Hernandez-Emulating-Samsungs-Baseband-For-Security-Testing.pdf) | Talk about FirmWire's first steps (back then, it had the working title ShannonEE). Discusses the fundamental architecture of the framework. |
| Reversing & Emulating Samsung’s Shannon Baseband                      | Hardwaer.io NL'20 | Team FirmWire (Grant & Marius)         | [youtube](https://www.youtube.com/watch?v=ypxgXNtvlgA) [slides](https://hardwear.io/netherlands-2020/presentation/samsung-baseband-hardwear-io-nl-2020.pdf)                  | Talk about the reverse engineering on Shannon-based modems which was required to build FirmWire.                                            |
| FirmWire: Transparent Dynamic Analysis for Cellular Baseband Firmware | NDSS'22           | Team FirmWire (Grant)                  | TBD                                                                                                                                                                          | Academic presentation of the FirmWire paper.                                                                                                |                                                  
| FirmWire: Taking Baseband Security Analysis to the Next Level         | CanSecWest'22     | Team FirmWire (Grant, Marius & Dominik | TBD                                                                                                                                                                          |                                                                                                                                             | Talk about the full FirmWire framework as released to the public                                                                                                                                            

## Blog posts

So far, we are not aware of any blog posts about FirmWire, but this may change in the future. ;)

## Adding your Vulnerability, Talk, or Blogpost to this Trophy Wall

We are happy to hear about your FirmWire usage! If you want to include it into this trophy wall, create first a fork of the FirmWire repository on the GitHub UI.
Then, clone the `docs` branch of your forked FirmWire repository:

```
$ git clone -b docs git@github.com:your_username/FirmWire.git
```

Afterwards, edit the `trophy_wall.md` file and add your resource to the according table, e.g. via:
```
$ vim FirmWire/docs/src/trophy_wall.md
```

Once done, push your changes and send us a PullRequest on [github](https://github.com/FirmWire/FirmWire)!
