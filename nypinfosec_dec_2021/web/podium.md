# Podium

> Who will be the champions? Watch this space.

> And listen up: There's a flag here too! Remember to place the flag in flag format NYP{WORD WORD WORD}

> Music and Styling: **Mark Bosco** Special Thanks to **Carl**.

> https://nypinfsecctf.tk/podium

## The Challenge

The link brings us to the podium page of the CTF. Turning on the volume, we can hear that the music rocks.

Opening `Inspect Element`, under the `<audio>` element, there is a comment that hints towards the need to find a script that was once on the page.

![image](https://user-images.githubusercontent.com/83258849/147806462-2bf67240-02d1-456e-bee0-53427d9694f4.png)

Similar to the `EW02 Framed Copy` challenge, we can use `Burp Suite` to see the response, checking if any JavaScript deletes itself after loading it on the web browser.

![image](https://user-images.githubusercontent.com/83258849/147806659-e763c292-ac63-4cc7-a677-f1cffd5cf673.png)

And we found the script!

Looking at the script, it has a random chance to pick 1 out of 4 of the different audio files to play on the page when it loads. The suspicious part of the script is this

```javascript
 if (random>99) {
  audio.src = "/files/4027335d1cfe58897648681aa003c013/a94k4045.mp3"
}
```

Since `random`'s max value can only be `100` based on this line `const random = Math.floor(Math.random() * 100);`, there is only a `1%` chance that this particular audio file will play. Let's try to save this file and see what is contained in the audio. Go to the endpoint through the link `https://nypinfsecctf.tk/files/4027335d1cfe58897648681aa003c013/a94k4045.mp3` to retrieve and save the file.

If we listen to the audio file, it is a sick rickroll remix with a somewhat christmas-y theme. But it is later disturbed with what sounds like morse code at the `47`th second through the audio.

We can try to extract the morse code audio from the audio file. I will be using `audacity` https://github.com/audacity/audacity.

Right after we open the audio file with `audacity`, we can see that there are 2 tracks, 1 for the rickroll audio while the other is the morse code.

![image](https://user-images.githubusercontent.com/83258849/147807050-02b2a8a9-1e7a-4247-919b-a63cdc6ecc6e.png)

We can split the audio tracks by clicking on the audio filename at the top left, then clicking on `Split Stereo Track`

![image](https://user-images.githubusercontent.com/83258849/147807123-6e0bd420-ed9c-4616-9406-027b8462265c.png)

The audio tracks will be splitted. Now we can delete the rickroll track by pressing the `Close` button on the top left of the audio track.

Now we remove the silent parts of the morse code audio so we dont have to wait for `47` seconds for the audio to play. Select the silence parts by dragging your mouse across it, then press `Ctrl+X` on the keyboard. Save the audio file as `morse.mp3`, then we can decode the message with the help of an online morse code decoder. I used https://morsecode.world/international/decoder/audio-decoder-adaptive.html.

Upload the file, then click play. It will automatically decrypt the morse code for you.

![image](https://user-images.githubusercontent.com/83258849/147807453-4a3e5de6-8985-4d7d-9db4-b7d0a85e6e18.png)

flag = `NYP{M0RSE CODE MAGIC}`
