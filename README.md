# ThreatMonitoring
I have written a program in Python3 which will get the hash of a running process, in this case chrome.exe. It will store it for 60 seconds and after 60 seconds if there is process termintation/relaunch then you will see new hash of that process. Any hash is only available for 60 seconds. Even if the same process continues to run then hash will be calculated again only it will be same as previous one.

Along with this, I am also tryng to showcase the traffic flow. When program runs you will be able to see the source and destination IP addresses, also source and destination ports.

Lets say if you terminate a process in the middle of the running program then you will see that there is no hash and also no traffic. And then if you start chrome again then you will see new hash and also traffic running. Also if the hash is same after 60 seconds, that means the same process is still running, then I am stopping traffic capture to demonstarte that I am discarding redundant data. (This traffic may vary based on how chrome is being used. But I have just taken a very simple case.)

Usage for HashAndTraffic.py

Open CMD on Windows.

C:\Users\nakul>python <path to HashAndTraffic.py> <process to monitor>

e.g.

C:\Users\nakul>python HashAndTraffic.py chrome.exe

Note: The traffic capture in this program may vary based on the process you are monitoring. I have written the code with chrome.exe.

Usage for Test_Hash_And_traffic_Pytest.py

You can run this file like this.

C:\Users\nakul>python Test_Hash_And_traffic_Pytest.py

This file is just testing representation of the file Hash_And_Traffic.py
