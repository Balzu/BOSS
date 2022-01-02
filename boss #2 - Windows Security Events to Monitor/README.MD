## Windows Security Events 

*security_events.csv* is a collection of Windows Events that should be monitored in order to detect anomalous situations that may indicate 
the infection of one or more hosts inside your network.

I provide this comprehensive list of events, mainly gathered from Microsoft online documentation and various blogs from security researchers, 
chosen based on my personal experience, to have a single and significative list of events that can be used as reference by Security Analysts and
Blue Teams.

The columns are quit self-explanatory:

- **Event ID** is the identifier of the event, as logged by the Windows Event Viewer.
- **Legacy** is *False* if this event is present in new versions of Windows, *True* if it is present in legacy versions of Windows (such as *XP* and *Server 2003*).
Events changed with different releases of Windows, and also the same event could have a different identifier in legacy Windows versions.
- **Potential Criticality** is an indicator, taken from Microsoft documentation, that tells how much critical the logged event could be. 
For instance, event 4672 is generally associated with an Administrator login: such event has an high potential criticality because it *may* indicate a successful 
exploitation that resulted in an *escalation of privilege* of the attacker, which previously owned a user account on the target machine while now owns an Administrator account
- **Description** is the description of the event.
