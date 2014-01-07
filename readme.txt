Dota 2 Fixups currently provides the following fixes for issues that occur when attempting to run a Dota 2 server.

* Fix clients receiving an error message when manually connecting to servers (due to not bringing lobby data with them).
* Fix third-party dedicated servers shutting down shortly after startup.
* Fix waiting for players stage being skipped.
* Enable existing dota_local_custom_* convars for dedicated servers for easier custom addon support.
* If custom addon desired, only load that addon's directory. (or dota_local_custom_allow_multiple 1 to keep all, with desired one first).
* Disables auto-exit when server version doesn't exactly match official server versions.
* Blocks server commands sent from the Game Coordinator backend.


Nicholas Hastings
nshastings@gmail.com