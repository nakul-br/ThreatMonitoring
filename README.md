# ThreatMonitoring
I have written a program in Python3 which will get the hash of a running process in this case chrome.exe. It will store it for 60 seconds and after 60 seconds if there is process termintation/relaunch then you will see new hash of that process. Any hash is only available for 60 seconds. Even if the same process continues to run then hash will be calculated again only it will be same as previous one.

Along with this I am also tryng to showcase the traffic flow. When program runs you will be able to see the source and destination IP addresses, also source and destination ports.

Lets say if you terminate a process in the middle of the running program then you will see that there is no hash and also no traffic. And then if you start chrome again then you will see new hash and also traffic running.
