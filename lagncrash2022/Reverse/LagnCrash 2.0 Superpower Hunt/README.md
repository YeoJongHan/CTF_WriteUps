This challenge consists of two parts, so we need to find two flags.

# Description
> A superhero origin story where you set out to get superpowers while you mourn the death of your cat, Lord Fuzzball.

We are given a `SuperpowerHunt.zip` file, unzipping it gives us a Unity compiled game with its resources.

## The Challenge
Launching the game brings us into this path with a huge cat clock. The game obviously isn't meant to be really a game as there are lack of resources and assets around.

![image](https://user-images.githubusercontent.com/83258849/160228950-3810717f-1612-494c-8c84-436e4e228cbc.png)

## Solution
I'm not sure if there is a way to decompile the Unity game files and logic back into C# code, but if there is, please let me know :)

I found the first part of the flag by opening the `level0` file with a text editor. This file can be found under the `LagnCrash 2.0 Superpower Hunt_Data` folder and it is a scene of the game, which usually represents a level in the game.

There are a lot of strings in this file. Upon opening the file, we can see a flag.

![image](https://user-images.githubusercontent.com/83258849/160229589-efeb00f1-643b-4510-8385-ff5b5844d098.png)

However, it is a fake flag.

Use Ctrl+F to find strings in the same file and we find two other flags, which would both be our real flags.

### Summary
This challenge can be made more challenging if the flags were inserted as game assets instead of just plain strings i suppose.

## Alternative Solution
Use Cheat Engine to teleport urself to the back of the cat.

We can find part 2 of the flag at the back of the cat.

![image](https://user-images.githubusercontent.com/83258849/160229693-5d135048-ffc4-46ce-8c2c-0f8ef398504c.png)

The other flag I suppose is at the top of the cat's head.
