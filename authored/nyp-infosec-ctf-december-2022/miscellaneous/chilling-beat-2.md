# Chilling Beat 2

| Difficulty | Points |
| ---------- | ------ |
| Easy       | 150    |

## Description

> I am now given these lines of data... what does these have to do with any chilling beats???

{% file src="../../../.gitbook/assets/data" %}

## Solution

### TL;DR

1. Find out that the data represents `HitObjects` in **Osu!**.
2. Using the `Bing Chiling` beatmap in `Edit` mode, we can open the `.osu` file and modify the `HitObjects` to the data given in the file.
3. Decode each `HitObject` to get the flag.

### Analysis

With **Osu!** opened and going to the `Bing Chiling` beatmap, we can click on **File > Open .osu in Notepad** to view the data (along with the HitObjects) in the `.osu` file.

<figure><img src="../../../.gitbook/assets/image (1) (4).png" alt=""><figcaption><p>Opening .osu file</p></figcaption></figure>

Scrolling down the `.osu` file, we can see lines of data under `HitObjects` that looks similar to the data given to us.

<figure><img src="../../../.gitbook/assets/image (1).png" alt=""><figcaption><p>HitObjects in .osu file</p></figcaption></figure>

<details>

<summary>data</summary>

```
94,318,1133,6,0,B|94:40|94:40|358:319|358:319|353:0,2,980
95,0,4796,2,0,B|253:158|253:158|405:-2|405:-2|252:158|252:158|256:232|257:263|259:404,2,840
164,373,8460,2,0,B|172:-54|172:-54|463:-4|447:57|397:150|280:171|72:186,2,980
310,351,12124,2,0,B|241:378|241:378|244:237|176:206|176:206|122:186|122:186|182:156|182:156|243:106|237:-44|237:-44|335:-6,2,700
136,219,22430,2,0,L|138:-8,2,210
136,224,75330,2,0,B|388:226,2,210
242,185,98117,2,0,P|381:276|176:327,1,490
234,199,110254,6,0,P|175:284|177:340,1,140
242,185,98117,2,0,P|381:276|176:327,1,490
234,199,110254,6,0,P|175:284|177:340,1,140
248,355,40407,2,0,B|118:295|118:295|253:205,1,280
109,22,34567,6,0,L|110:381,1,350
403,316,26781,6,0,L|62:314,2,280
395,226,106705,2,0,B|165:179|248:397|325:401|378:376|406:178,1,490
398,233,107735,2,0,L|466:371,1,140
186,146,59643,6,0,B|385:148,1,140
256,48,60101,2,0,B|255:334,1,280
403,316,26781,6,0,L|62:314,2,280
37,316,88727,2,0,B|133:12|133:12|272:301|272:301,1,630
274,294,89758,2,0,B|370:-10|370:-10|509:279|509:279,1,630
113,173,78308,6,0,L|413:172,1,280
403,173,78995,2,0,B|395:-35|71:-26|108:185,1,490
104,184,80140,2,0,B|88:379|369:339|439:300,1,420
403,316,26781,6,0,L|62:314,2,280
321,0,69033,6,0,L|323:367,1,350
326,359,69720,2,0,B|130:317|140:185|351:178,1,350
267,57,50941,6,0,B|119:180|119:180|397:183,1,420
267,57,51857,2,0,L|266:338,1,280
60,222,105330,2,0,L|63:370,1,140
78,365,105788,2,0,B|118:201|206:141|247:396,1,350
255,335,95712,2,0,P|38:131|250:26,1,630
249,53,93193,2,0,L|145:147,2,140
256,48,60101,2,0,B|255:334,1,280
60,222,105330,2,0,L|63:370,1,140
78,365,105788,2,0,B|118:201|206:141|247:396,1,350
225,0,115636,6,4,B|300:14|300:14|298:118|298:118|384:164|384:164|297:214|297:214|298:322|298:322|190:342,2,560,4|4|4,0:0|0:0|0:0,0:0:0:0:
```

</details>

We can see that the first 4 lines in the `data` file is exactly the same as the first 4 lines in the `.osu` file. This most likely represents our flag format **NYP{**

We can test this theory out by removing all the lines under `HitObjects` and replacing it with the first 4 lines in the `data` file. Sure enough, we get **NYP{**

Now do this for each and every line of code, noting down each 'stroke' of HitObject as two or more HitObjects may be required to combine into one character.

It should also be noted that the HitObjects may jump to certain timelines and the same HitObjects may be used more than once, so the whole `data` file cannot be copied and paste as is.
