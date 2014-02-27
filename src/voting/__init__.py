import hashlib
from struct import unpack, pack
from ConfigParser import ConfigParser
import os
import json
import time
from pyelliptic.openssl import OpenSSL

from debug import logger
from addresses import decodeAddress
from helper_sql import sqlExecute, sqlQuery
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
        
    def sendVote(self, fromAddress, answerNo):
        if answerNo < 0 or answerNo >= len( self.answers ):
            raise Exception( 'Invalid answer number: %d' % answerNo )
        ackdata = OpenSSL.rand(32)
        _, _, _, ripe = decodeAddress( self.chanAddress )
        subject = self.question
        data = self.encodeVote( answerNo )
        t = ('', self.chanAddress, ripe, fromAddress, subject, data,
             ackdata, int(time.time()), 'msgqueued', 1, 1, 'sent', 2)
        sqlExecute( 'INSERT INTO sent VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)', *t )
        shared.workerQueue.put(('sendmessage', self.chanAddress))
                
    def receivedVote(self, fromAddress, msgTime, data):
        answerNo, = self.decodeVote( data )
        if answerNo < 0 or answerNo >= len( self.answers ):
            logger.warning( "Vote (%d) received from %s in election '%s' is invalid number" %
                            ( answerNo, fromAddress, self.question ) )
            return
        
        logger.info( "Received vote (%d) from %s in election '%s'" %
                     ( answerNo, fromAddress, self.question ) )
        t = (self.chanAddress, fromAddress, msgTime, data, answerNo)
        sqlExecute( 'INSERT INTO votes VALUES (?,?,?,?,?)', *t )
    
    def encodeVote(self, answerNo):
        data = pack( '>I', answerNo )
        return data
    
    def decodeVote(self, data):
        answerNo, = unpack( '>I', data[0:4])
        return (answerNo,)
    
    def get_duplicate_vote_addresses(self):
        return sqlQuery( 'SELECT senderaddress FROM votes WHERE chanaddress=? GROUP BY senderaddress HAVING COUNT(*) > 1', self.chanAddress )
    
    def get_answers_and_votes(self):
        # Return rows each having (answerNo, amount_votes) for each answerNo having more than 0 votes
        # Doesn't count votes from addresses which have sent more than one vote
        votes_by_answer = dict( sqlQuery('''SELECT answer, COUNT(*) FROM votes WHERE chanaddress=? AND senderaddress NOT IN (
        SELECT senderaddress FROM votes WHERE chanaddress=? GROUP BY senderaddress HAVING COUNT(*) > 1)
        GROUP BY answer''', self.chanAddress, self.chanAddress ) )
        
        result = []
        
        for i in range( len( self.answers ) ):
            result.append( ( self.answers[i], votes_by_answer[i] if votes_by_answer.has_key(i) else 0 ) )

        return result
#         
#         print voterows
#         print "****************"
#         return voterows
#         # Find senders who have sent more than one vote
#         from collections import Counter
#         address_count = Counter( [ row[0] for row in voterows ])
#         duplicate_vote_addresses = [ address for address in address_count if address_count[address] > 1 ]
#         
#         # Remove duplicate vote senders from our votes
#         if len( duplicate_vote_addresses ) > 0:
#             logger.info( 'Duplicate votes detected from %d addresses: %s' % ( len( duplicate_vote_addresses ), duplicate_vote_addresses ) )
#         valid_votes = [ row[1] for row in voterows if row[0] not in duplicate_vote_addresses ]
# 
#         vote_count = Counter( valid_votes )
#         answer_votes = [ (self.answers[i], vote_count[i] ) for i in range( len( self.answers ) ) ]
#        logger.info( 'Valid votes: %d (%s)' % ( len( valid_votes ), valid_votes ) )
#        logger.info( 'Result: %s' % answer_votes )
#        logger.info( '%s' % vote_count )        
#         return answer_votes
        
    def compute_result(self):
        pass
    
    def createChanLabel(self):
        return str( "%s %s" % ( self.chanLabelPrefix, self.question ) )
    
    def saveToFile(self, filename):
        cp = ConfigParser()
        cp.add_section( Election.voteFileSection )
        cp.set( Election.voteFileSection, "question", self.question )
        cp.set( Election.voteFileSection, "answers", json.dumps( self.answers, encoding='ascii' ) )
        cp.set( Election.voteFileSection, "voters", json.dumps( self.voters, encoding='ascii' ) )
        if self.hash is None:
            self.computeAndCheckHash()
        cp.set( Election.voteFileSection, "hash", self.hash )
        if self.chanAddress is None:
            self.computeAndCheckChanAddress()
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