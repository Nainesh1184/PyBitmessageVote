'''
Created on 18/09/2014

@author: Jesper
'''
import datetime, hashlib, time

from addresses import decodeVarint, encodeVarint
from debug import logger

from consensus_helper import ConsensusHelper

class ConsensusData:
    '''
    classdocs
    '''
    
    DATA_TYPE_PLAIN = 1
    DATA_TYPE_VOTING = 10
    
    cp = None

    def __init__(self, type, blockchain, time_data):
        """
        type is the DATA_TYPE_* type indicator
        blockchain is which blockchain to use for commitments (ConsensusProtocol.BLOCKCHAIN_*)
        time_data is an instance of the ConsensusTimeData class
        """
        self.type = type
        self.blockchain = blockchain
        self.time_data = time_data
        
    def initialize( self ):
        """
        Initialization function, override this in extending classes.
        Run all initialization here instead of in the constructor
        """
        pass
            
    def message_valid( self, data ):
        """
        Message validation function, override this in extending classes
        """
        return True
    
    def compute_results( self, accepted_messages ):
        """
        Result computation function, override this in extending classes
        """
        return "Result!"
    
    def pack_binary( self ):
        """
        Pack the data into a binary string for storage in DB.
        Remember to start with ConsensusData.pack_binary_header(type, time_data)
        Override this in extending classes
        """
        return ConsensusData.pack_binary_header(ConsensusData.DATA_TYPE_PLAIN, self.time_data)
    
    def compute_hash( self ):
        """
        Hash computation function, should return a hex digest of all the data.
        Used for computing the chan address.
        Override this in extending classes
        """
        sha = hashlib.new( 'sha256' )
        sha.update( str( self.blockchain ) + str( self.time_data ) )
        return sha.hexdigest()
    
    def status_changed(self, new_status):
        print "Status changed to: %d" % new_status
        
    def is_testnet_blockchain(self):
        from consensus_protocol import ConsensusProtocol
        return self.blockchain == ConsensusProtocol.BLOCKCHAIN_BITCOIN_TESTNET
    
    def to_json(self):
        return { "type": self.type, "blockchain": self.blockchain, 
                 "time_data": self.time_data.to_json() }
        
    @staticmethod
    def pack_binary_header(type, blockchain, time_data ):
        """
        Pack the header data (type, timeData) into a binary string
        The format is 
        [ dataType(varInt) ]
        [ blockchain(varInt) ]
        [ timeDataLength(varInt) ]
        [ timeData ]
        [ actual data ]
        """
        result = encodeVarint( type )
        result += encodeVarint( blockchain )
        time_data_bin = time_data.pack_binary()
        result += encodeVarint( len( time_data_bin ) )
        result += time_data_bin
        return result
        
    @staticmethod
    def unpack_binary( data, dont_check=False ):
        read_pos = 0
        
        data_type, offset = decodeVarint( data[read_pos:read_pos+10] )
        read_pos += offset
        blockchain, offset = decodeVarint( data[read_pos:read_pos+10] )
        read_pos += offset
        
        time_data_bin_length, offset = decodeVarint( data[read_pos:read_pos+10] )
        read_pos += offset
        time_data_bin = data[read_pos:read_pos+time_data_bin_length]
        read_pos += time_data_bin_length
        time_data = ConsensusTimeData.unpack_binary( time_data_bin )
        
        result = None
        if data_type == ConsensusData.DATA_TYPE_PLAIN:
            result = ConsensusData( data_type, blockchain, time_data )
        elif data_type == ConsensusData.DATA_TYPE_VOTING:
            from voting_data import VotingData
            result = VotingData.unpack_binary( data[read_pos:], blockchain, time_data, dont_check )
        
        time_data.data = result
        return result

    
class ConsensusTimeData:
    """
    A consensus has the following time definitions:
        start: The official time to start posting messages (adjusted block timestamp)
        post_deadline: The official time to stop posting messages (adjusted block timestamp)
        commitment_phase_deadline: The official deadline to end the commitment phase start the results phase
            (adjusted block timestamp)
    """
    
    def __init__(self, start, post_deadline, commitment_phase_deadline ):
        self.start = start
        self.post_deadline = post_deadline
        self.commitment_phase_deadline = commitment_phase_deadline
        self.sanity_checks()
        
    def sanity_checks(self):
        """
        Check that the values make sense
        """
        if self.start < 0:
            raise Exception( 'Start timestamp must be positive' )
        if self.post_deadline < 0:
            raise Exception( 'Deadline timestamp must be positive' )
        if self.post_deadline <= self.start :
            raise Exception( 'Deadline must be after start' )
        if self.commitment_phase_deadline <= self.post_deadline:
            raise Exception( 'Commitment phase deadline must be after deadline' )
        
    def to_json(self):
        return { "start": self.start, "post_deadline": self.post_deadline, 
                 "commitment_phase_deadline": self.commitment_phase_deadline }
        
    def pack_binary(self):
        """
        Packs all variables into a binary string.
        For now, every variable is assumed to be an integer
        Format is as follows:
        [ start(varInt) ][ post_deadline(varInt) ]
        [ commitment_phase_deadline(varInt) ]
        """
        result  = encodeVarint( self.start )
        result += encodeVarint( self.post_deadline )
        result += encodeVarint( self.commitment_phase_deadline )
        return result
    
    @staticmethod
    def unpack_binary( data ):
        read_pos = 0
        
        start, offset = decodeVarint( data[read_pos:read_pos+10] )
        read_pos += offset
        
        post_deadline, offset = decodeVarint( data[read_pos:read_pos+10] )
        read_pos += offset
        
        commitment_phase_deadline, offset = decodeVarint( data[read_pos:read_pos+10] )
        read_pos += offset
        
        return ConsensusTimeData( start, post_deadline, commitment_phase_deadline )
        
    def __str__(self):
        return "ConsensusTimeData<%s,%s,%s>" % ( time.strftime( '%c', time.gmtime(self.start) ), time.strftime( '%c', time.gmtime(self.post_deadline) ), time.strftime( '%c', time.gmtime(self.commitment_phase_deadline) ) )
        