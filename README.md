PyBitmessageVote
================
This repository contains the proof-of-concept implementation of the voting
scheme presented in my Master's thesis in Computer Science at the University
of Copenhagen.

The implementation is built on the code from the PyBitmessage reference client
for the Bitmessage network.


Thesis abstract
---------------
This thesis proposes a protocol to conduct anonymous, trustless, decentralized elections over the internet. Only registered voters can vote, multiple votes from the same voter are easily detected and discard, and it is impossible to determine the identity behind a given vote with a better probability than random guessing.

The voting protocol builds on top of a *decentralized deadline consensus protocol* which can form a consensus about which messages have been sent before a specific deadline. This protocol can also be used to suit other purposes, e.g., contests, auctions and applications. All in a decentralized manner.

The protocols use elliptic curve cryptography, Bitcoin and blockchain-technology, the Bitmessage protocol, Linkable Ring Signatures and Invertible Bloom Lookup Tables.

A proof-of-concept client has been developed and implemented, where one can create and execute elections on simple questions.


PyBitmessage
============

Bitmessage is a P2P communications protocol used to send encrypted messages to
another person or to many subscribers. It is decentralized and trustless,
meaning that you need-not inherently trust any entities like root certificate
authorities. It uses strong authentication, which means that the sender of a
message cannot be spoofed, and it aims to hide "non-content" data, like the
sender and receiver of messages, from passive eavesdroppers like those running
warrantless wiretapping programs.


Development
----------
Bitmessage is a collaborative project. You are welcome to submit pull requests 
although if you plan to put a non-trivial amount of work into coding new
features, it is recommended that you first solicit feedback on the DevTalk
pseudo-mailing list:
BM-2D9QKN4teYRvoq2fyzpiftPh9WP9qggtzh


References
----------
* [Project Website](https://bitmessage.org)
* [Protocol Specification](https://bitmessage.org/wiki/Protocol_specification)
* [Whitepaper](https://bitmessage.org/bitmessage.pdf)
* [Installation](https://bitmessage.org/wiki/Compiling_instructions)
