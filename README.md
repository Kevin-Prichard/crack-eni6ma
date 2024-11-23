# crack-eni6ma
Attempt to crack passwords entered thru eni6ma (as we understand it today), comparing snapshotted login charset panels across multiple session

## Background
Authentication input systems in 2024 are highly susceptible to passcode theft.  Examples abound in security research journals and local news accounts of 1:1 passcode, PIN and password theft-
- debit card and keypad skimmers, which copy a debit card's magnetic stripe and the cardholder's PIN
- last four digits of social security number being used to secure financial accounts at financial institutions
- monitoring a user's mobile or laptop keyboard during unlock

## Introduction

The author of Eni6ma claims to have created a novel authentication scheme.

Eni6ma proposes to make user inputs of their PIN (password, passcode, passphrase, ...) difficult to steal by channeling the entry of same through a series of multiple-choice questions, following this loop-
1. Present user with four panels, containing approximately 24 characters each, from the user's locale character set (alpha + numeric + punctuation)
2. The characters displayed in each panel are randomly chosen from the charset, such that there are no duplicate characters shared between panels, and each time a new set of panels is generated and presented the set of characters contained by each is random and highly likely to be different from te preceding panels
3. For the current passcode character up for entry, the user chooses the panel in which the character appears, using one of four buttons associated with each panel (arrow or color buttons at present)
4. After selection of the correct panel, the current passcode character position number is incremented, and this process loops back to 1
5. This process continues until all passcode characters have been correctly identified, then the loop exits


## In this repository
In eni6ma-crackers.py, I attempted to recreate the 4-panel, randomized selection process that users authenticating with the system will follow.  The panel selected by the user is snapshotted by the script for later analysis (function `perform_many_logins()`).

In `analyse_login_attempts()`, we review the collected panel snapshots by intersecting them as sets, from across all the login sessions and for each character position of the password under consideration.  The purpose here is to throw away characters that are not the same per password character position, retaining only the character(s) that match across login sessions.  When the number of intersected characters per position reaches 1, the review is finished and returns.


## Results
... to be determined following review ...
