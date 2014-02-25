import hashlib
from struct import unpack, pack
from ConfigParser import ConfigParser
import os
import json

from addresses import decodeAddress
import shared

class Election:
    chanLabelPrefix = '[vote]'
    voteFileSection = 'VOTE'
    
    def __init__(self, question, answers, voters, hash=None, chanAddress=None, dontCheck=False):
        self.question = question
        self.answers = answers
        self.voters = voters
        self.hash = hash
        self.chanAddress = chanAddress
        self.checkValues()
        if not dontCheck:
            self.computeAndCheckHash()
            self.computeAndCheckChanAddress()
        
    def checkValues(self):
        if len( self.question ) == 0:
            raise Exception( 'No question provided' )
        
        if len( self.answers ) <= 1:
            raise Exception( 'At least two answers must be provided' )
        
        if len( self.voters ) <= 2:
            raise Exception( 'At least three voter addresses must be provided' )
        
        invalidAddresses = [a for a in self.voters if decodeAddress(a)[0] != 'success']
        if len( invalidAddresses ) > 0:
            raise Exception( 'Invalid addresses: %s' % invalidAddresses )
                
    def computeAndCheckHash(self):
        sha = hashlib.new( 'sha256' )
        hashedString = self.question + ";" + ",".join( self.answers ) + ";" + ",".join( self.voters )
        sha.update( hashedString )
        calculatedHash = sha.hexdigest()
        if self.hash != None and self.hash != calculatedHash:
            raise Exception( 'Hash mismatch' )
        
        self.hash = calculatedHash
        
    def computeAndCheckChanAddress(self):
        shared.apiAddressGeneratorReturnQueue.queue.clear()
        # command, addressVersionNumber, streamNumber, label, numberOfAddressesToMake, deterministicPassphrase, eighteenByteRipe
        shared.addressGeneratorQueue.put(('getDeterministicAddress', 4, 1, self.createChanLabel(), 1, self.hash, False))
        chanAddress = shared.apiAddressGeneratorReturnQueue.get()
        if self.chanAddress != None and self.chanAddress != chanAddress:
            raise Exception( 'Wrong chan address' )
        
        self.chanAddress = chanAddress
        
    def isAlreadyJoined(self):
        return shared.config.has_section( self.chanAddress )
        
    def joinChan(self):
        if self.isAlreadyJoined():
            with shared.printLock:
                print "Voting chan", self.chanAddress, "already joined. Wont join again"
            return
        shared.apiAddressGeneratorReturnQueue.queue.clear()
        # command, chanAddress, label, deterministicPassphrase
        shared.addressGeneratorQueue.put(('joinChan', self.chanAddress, self.createChanLabel(), self.hash))
        chanAddresses = shared.apiAddressGeneratorReturnQueue.get()
        if len( chanAddresses ) != 1 or chanAddresses[0] != self.chanAddress:
            raise Exception( 'Invalid result from joinChan: %s' % chanAddresses )
        
        # Add extra voting parameters to the config file
        shared.config.set( self.chanAddress, "vote", 'true' )
        shared.config.set( self.chanAddress, "question", self.question )
        shared.config.set( self.chanAddress, "answers", json.dumps( self.answers ) )
        shared.config.set( self.chanAddress, "voters", json.dumps( self.voters ) )
        
        self.flush_shared_config()
        
    def createChanLabel(self):
        return str( "%s %s" % ( self.chanLabelPrefix, self.question ) )
    
    def saveToFile(self, filename):
        cp = ConfigParser()
        cp.add_section( Election.voteFileSection )
        cp.set( Election.voteFileSection, "question", self.question )
        cp.set( Election.voteFileSection, "answers", json.dumps( self.answers, encoding='ascii' ) )
        cp.set( Election.voteFileSection, "voters", json.dumps( self.voters, encoding='ascii' ) )
        cp.set( Election.voteFileSection, "hash", self.hash )
        cp.set( Election.voteFileSection, "chanAddress", self.chanAddress )
        
        with open( filename, 'w' ) as f:
            cp.write( f )
            
    def delete(self):
        if not self.isAlreadyJoined():
            return
        
        shared.config.remove_section( self.chanAddress )
        self.flush_shared_config()
        
    def flush_shared_config(self):
        with open(shared.appdata + 'keys.dat', 'w') as configfile:
            shared.config.write(configfile)
    
    @staticmethod   
    def readFromFile(filename):
        print "Reading election from %s" % (filename)
        cp = ConfigParser()
        with open( filename, 'r' ) as f:
            cp.readfp( f, filename )
        print cp.sections()
        return Election( cp.get( Election.voteFileSection, "question" ),
                         json.loads( cp.get( Election.voteFileSection, "answers" ) ),
                         json.loads( cp.get( Election.voteFileSection, "voters" ) ),
                         cp.get( Election.voteFileSection, "hash" ),
                         cp.get( Election.voteFileSection, "chanAddress" ) )
        
    @staticmethod
    def readFromAddress(address):
        if not shared.config.has_section( address ):
            return None
        if not shared.config.getboolean( address, 'vote' ):
            return None
        
        return Election( shared.config.get( address, 'question' ),
                         json.loads( shared.config.get( address, 'answers' ) ),
                         json.loads( shared.config.get( address, 'voters' ) ),
                         chanAddress=address,
                         dontCheck=True )
        
        
        
    def __str__(self):
        return "Election<%s (%d,%d,%s,%s)>" % ( self.question, len( self.answers ), len( self.voters ), self.chanAddress, self.hash )