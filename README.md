# TCP Port Scanner

* fullTCP.py: scans the target with full TCP hanshake.


* rawSocketScanner.py: scans the target with half-open TCP connection,the proccess is to make a packet from from scratch and set SYN flag to 1, it's also possible to modify this  scanner to perform FIN or X-mass scans.

# TODO:

- add threaded option to scan faster when it comes to multi target scans
- add proxy option to relay connections through a custom local proxy, for example TOR