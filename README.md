# Check All APK's - scripts for checking your phone for malware

Check All APK's is a set of two scripts that leverage 
[Drozer](https://labs.mwrinfosecurity.com/tools/drozer/) and the 
[VirusTotal API](https://www.virustotal.com/en/documentation/public-api/) to check whether a phone
is running applications known to be malware. This is practical during security breaches, when an
analyst has to identify malicious applications among hundreds of legitimate ones.

This code is part of an article published by Kudelski Security in August, 2017. The full article can
be found here:
[https://research.kudelskisecurity.com/2017/08/07/checking-android-for-known-malware](https://research.kudelskisecurity.com/2017/08/07/checking-android-for-known-malware)

# Requirements

Check All APK's scripts are coded in Python 2.7. It uses two packages:

* Drozer, which can be downloaded as a Debian DEB package on MWR InfoSecurity's website 
[(see above)](https://labs.mwrinfosecurity.com/tools/drozer/)
* pwntools, a CTF framework and exploit development library 
  [https://github.com/Gallopsled/pwntools](https://github.com/Gallopsled/pwntools)
  and can be installed either from source or via pip.

In addition to the python packages, the check_all_apks.py script makes calls to the Android Debug
Bridge, which can be installed as part of Android Studio or via the APT repository.

Finally, check_virustotal.py leverages the virustotal API - you will need to register for a free
account to leverage this service.

# Usage

Download this repository and set up its dependencies. Set your phone to Development mode and enable 
USB debugging. Connect your phone to your computer and test that you are able to interface with it, 
using ```adb shell``` for example. Next, install the drozer agent on the phone. 

To dump a list of packages and MD5 hashes into a file called package_hashes.txt, run the
check_all_apks.py script. Alternatively, you can use the "thorough" mode to download the APK's and
create SHA256 hashes of the packages. Once you have this file, you can run the check_virustotal.py
script to iteratively check all packages for hits. For more details on the installation, please
consult the blog post on the Kudelski Security research blog.

# Author

The Check All APK's scripts were written by [Rick El-Darwish](https://github.com/inf0junki3).

# Intellectual property

Copyright 2017 Nagravision SA, all rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
