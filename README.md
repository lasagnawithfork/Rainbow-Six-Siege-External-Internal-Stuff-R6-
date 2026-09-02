# Rainbow-Six-Siege-External-Internal-Stuff-R6-
R6



Information about new anti cheat :
- new script detection

 Service called "sen_service" appears to be Ubisoft anti-cheat service
 As far as we know there is also **RING 0** DETECTION while not confirmed, it is very high-likely; 
 

I will also continue updating this source too after some time
  this repository will contain

   External Source Code fully working.
    Internal Source code I'm not really familiar with therefore There's a very unlikely chance I'll even bother with it

  High in depth is that r6 uses sigs. 
   This is all I've identified for now 
   88e15f23:WorldToScreen
   ***Current WorldToScreenClassID**

  I'm doing allot of research about R6 Generally posting information and sources if I get my hands on the knowledge behind it.


## HOW TO FIND GAME MANAGER

Open ida with your game build.
Search R6TextChatManager -> XREF IT ->  jump to addy sub_blabla_

**v26 ^ v27 = game manager it's always added or 3xb something similar  the letter in the middle can change over patches or seasons.



