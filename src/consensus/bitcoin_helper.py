'''
Created on 26/09/2014

@author: Jesper
'''

import sys
sys.path.append( '.' )

import hashlib, json, Queue, random, threading, time, urllib2

import highlevelcrypto, shared

from debug import logger

import helper_keys
from pyelliptic import arithmetic
import bitcoin

from consensus_helper import ConsensusHelper

# Set to True to log debug info
DEBUG = True

class BitcoinThread(threading.Thread):
    '''
    classdocs
    '''
    
    BLOCKR_API_BASE_URL = "http://btc.blockr.io/api/v1/"
    BLOCKR_API_BASE_URL_TESTNET = "http://tbtc.blockr.io/api/v1/"
    
    # The minimum amount of BTC in an unspent output to use
    # The amount of BTC to use to commit to something
    BTC_COMMITMENT_AMOUNT = 0.0000543
    SATOSHI_COMMITMENT_AMOUNT = int( BTC_COMMITMENT_AMOUNT * 100000000 )
    BTC_TRANSACTION_FEE =   0.0001
    SATOSHI_TRANSACTION_FEE =   int( BTC_TRANSACTION_FEE   * 100000000 )
    BTC_UNSPENT_MIN_AVAILABLE = BTC_COMMITMENT_AMOUNT + BTC_TRANSACTION_FEE
    SATOSHI_UNSPENT_MIN_AVAILABLE = int( BTC_UNSPENT_MIN_AVAILABLE * 100000000 )
    
    MINIMUM_ALARM_CHECK_DELAY_SECONDS = 30 # 2 minutes
    
    AMOUNT_BLOCKS_TO_REQUEST_AT_A_TIME = 5
    BITCOIN_AVERAGE_BLOCK_TIME_SECONDS = 10 * 60 # 10 minutes
    
    # Amount of expected waiting time for timestamp alarms
    # that we actually wait until checking again (as a ratio) 
    TIMESTAMP_ALARM_EXPECTED_WAIT_RATIO = 0.3
    
    ADJUSTED_TIMESTAMP_AMOUNT_BLOCKS = 11
    ADJUSTED_TIMESTAMP_SECONDS_ADD = int(((ADJUSTED_TIMESTAMP_AMOUNT_BLOCKS-1)/2.0) * BITCOIN_AVERAGE_BLOCK_TIME_SECONDS)
        
    
    
    work_queue = Queue.Queue()
    result_queue = Queue.Queue()
    
    singleton = None

    def __init__(self):
        threading.Thread.__init__(self)
        if BitcoinThread.singleton is None:
            BitcoinThread.singleton = self
        else:
            raise Exception( 'Only one BitcoinThread can be initialized' )
        
        # List of ( testnet, n, timestamp, callback )-tuples
        self.timestamp_alarms = []
        self.next_timestamp_check = None
        # [ non_testnet, testnet ]
        self.latest_adjusted_timestamp = [ None, None ]
        
        # Has entry for both testnet=True and False
        self.latest_block_number = {True: None, False: None}

    @staticmethod
    def enqueue(caller, command, params, callback=None):
        BitcoinThread.work_queue.put( ( caller, command, params, callback ) )
        
    @staticmethod
    def get_latest_adjusted_timestamp(testnet):
        """
        If the thread doesn't already have fetched the latest adjusted timestamp,
        start fetching it and block until it is done. 
        Returns a ( localtime, adjusted_timestamp, block_no )
        for the latest retrieved adjusted timestamp
        """
        index = 1 if testnet else 0
        t = BitcoinThread.singleton
        if t.latest_adjusted_timestamp[index] is None:
            t.getAdjustedBlockTimestamp(testnet)
        return t.latest_adjusted_timestamp[index]

    @staticmethod
    def get_first_seen(testnet, address):
        return BitcoinThread.singleton.getFirstSeen( testnet, address )
    @staticmethod
    def get_address(testnet, content):
        return BitcoinThread.singleton.getAddress( testnet, content )
    @staticmethod
    def get_corresponding_address(testnet, address, pubSigningKey=None ):
        return BitcoinThread.singleton.getCorrespondingAddress( testnet, address, pubSigningKey )
    @staticmethod
    def get_first_block_with_adjusted_timestamp(testnet, adjusted_timestamp):
        return BitcoinThread.singleton.getFirstBlockWithAdjustedTimestamp( testnet, adjusted_timestamp )
    @staticmethod
    def commit_to(testnet, commit_address, private_key):
        return BitcoinThread.singleton.commitTo(testnet, commit_address, private_key)
    @staticmethod
    def clear_alarms(caller):
        alarms = [alarm for alarm in BitcoinThread.singleton.timestamp_alarms if alarm.caller == caller]
        map( lambda alarm: BitcoinThread.singleton.timestamp_alarms.remove( alarm ), alarms )
    @staticmethod
    def estimate_seconds_until_adjusted_timestamp(testnet, adjusted_timestamp):
        current_adjusted_timestamp = BitcoinThread.get_latest_adjusted_timestamp(testnet)[1]
        return BitcoinThread.singleton.__estimate_time_until_adjusted_timestamp(adjusted_timestamp, current_adjusted_timestamp)
    
    def run(self):
        while True:
            queue_timeout = None
            check_timestamp = False
            next_check = None
            
            if self.next_timestamp_check is not None:
                next_check = self.next_timestamp_check 
                
            if next_check is not None:
                queue_timeout = next_check - time.time()
                log_debug( "Next check is in %d seconds (%s)" % ( queue_timeout, time.strftime( '%c', time.gmtime( next_check ) ) ) )
                
            try:
                caller, command, params, callback = BitcoinThread.work_queue.get(timeout=queue_timeout)
                
                result = None
                
                if command == 'getUnspentTransactions':
                    if len( params ) != 2:
                        raise Exception( "You must provide testnet and a list of addresses." )
                    
                    testnet, addresses = params
                    
                    result = [self.getUnspentTransactions( testnet, addresses )] or []
                    
                elif command == 'commitTo':
                    
                    if len( params ) != 3:
                        raise Exception( "commitTo parameters: ( testnet, address, private_key )")
                    testnet, address, private_key = params
                        
                    result = self.commitTo( testnet, address, private_key )
                    
                elif command == 'setTimestampAlarm':
                    """
                    Request a callback when the blockchain time has exceeded
                    a certain timestamp. 
                    Exceeded meaning getAdjustedBlockTimestamp(testnet, None) returns
                    a timestamp >= <timestamp> 
                    Callback function params( adjusted_timestamp, block_no )
                    """
                    if len( params ) != 2:
                        raise Exception( "setTimestampAlarm params: ( testnet, timestamp )")
                    
                    testnet, timestamp = params
                    alarm = TimestampAlarm( caller, testnet, timestamp, callback )
                    self.timestamp_alarms.append( alarm )
                    self.timestamp_alarms.sort( key=lambda ta: ta.timestamp )
                    log_debug( "New timestamp alarm set: %s" % ( alarm, ) )
                    
                    # Check the timestamps immediately
                    check_timestamp = True
                    
                    # Prevent the callback from being called immediately
                    callback = None
                    
                elif command == 'shutdown':
                    break
                    
                else:
                    raise Exception( "BitcoinThread: unknown command '%s'" % command )
                
                if callback is not None:
                    callback( *result )
                    
            except Queue.Empty:
                # Timeout occurred
                pass
                
            if check_timestamp or ( self.next_timestamp_check is not None and time.time() >= self.next_timestamp_check ):
                self.check_timestamp_alarms()
            
    def __get_median_timestamp(self, blocks):
        # Sort all blocks by timestamp
        sorted_blocks = sorted( blocks, key=lambda b: b["time_utc"] )
        length = len( sorted_blocks )
        if length % 2:
            return int( ConsensusHelper.parse_utc_timestamp( sorted_blocks[length/2]["time_utc"] ) )
        else:
            return int( ( ConsensusHelper.parse_utc_timestamp( sorted_blocks[length/2]["time_utc"] ) + \
                          ConsensusHelper.parse_utc_timestamp( sorted_blocks[length/2-1]["time_utc"] ) ) / 2.0 )
        
    
    def getAdjustedBlockTimestamp(self, testnet, block_no=None):
        """
        Compute the adjusted block timestamp,
        which is equal to the median timestamp of this block and the previous 10
        (11 blocks in total)
        PLUS one hour
        (one hour because 6 * 10 mins for each block)
        If block_no is None, retrieve the latest block number
        
        Store ( adjusted_timestamp, block_no ) in self.latest_adjusted_timestamp if newer than
        what we already have
        
        Returns timestamp, block_no
        """
        
        if block_no is None:
            last_block = self.request_blockr_json("block/info/last", testnet)
            block_no = last_block["nb"]
            
        block_numbers_comma_sep = ",".join( [ str(i) for i in range( block_no-BitcoinThread.ADJUSTED_TIMESTAMP_AMOUNT_BLOCKS+1, block_no+1 ) ] )
        # Get all blocks
        blocks = self.request_blockr_json( "block/info/%s" % block_numbers_comma_sep, testnet )
        timestamp = self.__get_median_timestamp( blocks )
            
        # Adjust with seconds
        timestamp += BitcoinThread.ADJUSTED_TIMESTAMP_SECONDS_ADD
        
        self.__new_adjusted_timestamp(testnet, timestamp, block_no)
            
        return timestamp, block_no
    
    def getFirstBlockWithAdjustedTimestamp(self, testnet, adjusted_timestamp):
        """
        Returns the block number of the first block whose adjusted timestamp >= <timestamp>.
        Returns None if no such block exists.
        
        Store ( adjusted_timestamp, block_no ) in self.latest_adjusted_timestamp if newer than
        what we already have
        """

        # The earliest possible timestamp of the block that is the median
        middle_timestamp = adjusted_timestamp - BitcoinThread.ADJUSTED_TIMESTAMP_SECONDS_ADD
        
        log_debug( "getFirstBlockWithAdjustedTimestamp( testnet=%s, timestamp=%s, middle=%s )" % ( testnet, time.strftime( '%c', time.gmtime( adjusted_timestamp ) ), time.strftime( '%c', time.gmtime( middle_timestamp ) ) ) )
        
        # First find the first block on or after middle_timestamp
        block = self.request_blockr_json( "block/info/first?after=%d" % ( middle_timestamp ), testnet )
        if block is None:
            return None
        
        # block is the earliest possible block to be the median,
        # so we'll have to retrieve AMOUNT_BLOCKS / 2 before that block
        # and at least AMOUNT_BLOCKS / 2 after that block.
        # (We'll take some more after to ensure that we'll find the block we need) 
        block_numbers_to_check = range( block["nb"] - BitcoinThread.ADJUSTED_TIMESTAMP_AMOUNT_BLOCKS / 2 - 1,
                                        block["nb"] + BitcoinThread.ADJUSTED_TIMESTAMP_AMOUNT_BLOCKS )
        block_numbers_comma_sep = ",".join( [ str(i) for i in block_numbers_to_check ] )
        
        blocks = self.request_blockr_json( "block/info/%s" % block_numbers_comma_sep, testnet )
        
        while True:
        
            for i in range( len( blocks ) - BitcoinThread.ADJUSTED_TIMESTAMP_AMOUNT_BLOCKS + 1 ):
                # Go through all sequences with <AMOUNT_BLOCKS> blocks and take
                # the first whose adjusted_timestamp >= the required adjusted timestamp
                
                median_timestamp = self.__get_median_timestamp( blocks[ i : i+BitcoinThread.ADJUSTED_TIMESTAMP_AMOUNT_BLOCKS ] )
                current_adjusted_timestamp = median_timestamp + BitcoinThread.ADJUSTED_TIMESTAMP_SECONDS_ADD
                
                first_block = blocks[i]
                last_block = blocks[i+BitcoinThread.ADJUSTED_TIMESTAMP_AMOUNT_BLOCKS-1]
                log_debug( "Adjusted timestamp for blocks %d-%d is %s (median: %s)" % ( first_block["nb"], last_block["nb"], time.strftime( '%c', time.gmtime( current_adjusted_timestamp ) ), time.strftime( '%c', time.gmtime( median_timestamp ) ) ) )
                
                if current_adjusted_timestamp >= adjusted_timestamp:
                    block_no = last_block["nb"]
                    self.__new_adjusted_timestamp(testnet, current_adjusted_timestamp, block_no)
                    return block_no
                
            last_block = blocks[len(blocks)-1]
            new_blocks_to_check = range( last_block['nb'] + 1, last_block['nb'] + BitcoinThread.ADJUSTED_TIMESTAMP_AMOUNT_BLOCKS + 1 )
            new_blocks_comma_sep = ",".join( [ str(i) for i in new_blocks_to_check ] )
            new_blocks = self.request_blockr_json( "block/info/%s" % new_blocks_comma_sep, testnet )
            if new_blocks is None:
                return None
            if type( new_blocks ) == type( [] ):
                blocks.extend( new_blocks )
            else:
                blocks.append( new_blocks )
    
    def __new_adjusted_timestamp(self, testnet, timestamp, block_no):
        index = 1 if testnet else 0
        # Update self.latest_adjusted_timestamp if we get a newer one 
        if self.latest_adjusted_timestamp[index] is None or self.latest_adjusted_timestamp[index][1] < timestamp:
            self.latest_adjusted_timestamp[index] = ( time.time(), timestamp, block_no )
        
    def getAddress(self, testnet, content):
        """
        Compute (deterministically) a Bitcoin address from the provided content.
        Set the testnet boolean to True to compute a testnet address
        """
        ripe = hashlib.new('ripemd160')
        sha = hashlib.new('sha256')
        sha.update(content)
        ripe.update(sha.digest())
        netPrefix = '\x6F' if testnet else '\x00'
        ripeWithPrefix = "%s%s" % ( netPrefix, ripe.digest() )
    
        checksum = hashlib.sha256(hashlib.sha256(
            ripeWithPrefix).digest()).digest()[:4]
        binaryBitcoinAddress = ripeWithPrefix + checksum
        numberOfZeroBytesOnBinaryBitcoinAddress = 0
        while binaryBitcoinAddress[0] == '\x00':
            numberOfZeroBytesOnBinaryBitcoinAddress += 1
            binaryBitcoinAddress = binaryBitcoinAddress[1:]
        base58encoded = arithmetic.changebase(binaryBitcoinAddress, 256, 58)
        return "1" * numberOfZeroBytesOnBinaryBitcoinAddress + base58encoded
    
    def getCorrespondingAddress(self, testnet, bmAddress, pubSigningKey=None):
        """
        Returns the corresponding Bitcoin-address to the provided Bitmessage-address.
        Only returns the address if we have the private keys for the Bitmessage-address,
        otherwise None
        If you have the public signing key for the address, that's good enough also.
        """
        pubSigningKey = pubSigningKey or helper_keys.getPublicSigningKey( bmAddress )
        if pubSigningKey is None:
            return None
            
        return self.getAddress( testnet, pubSigningKey )
        
    
    def getFirstSeen(self, testnet, address):
        """
        Find out when the blockchain has first seen the provided address.
        Returns first transaction info if it has been seen, or None if never seen before.
        Result is ( block_number, confirmation_count, block_timestamp ) 
        """
        address_info = BitcoinThread.request_blockr_json( "address/info/%s" % address, testnet )
        if address_info['is_unknown'] or not 'first_tx' in address_info:
            return None
        first_tx = address_info['first_tx']
        return ( int( first_tx['block_nb'] ), 
                 first_tx['confirmations'], 
                 int( ConsensusHelper.parse_utc_timestamp( first_tx['time_utc'] ) ) )
    
    def getUnspentTransactions(self, testnet, addresses):
        """
        Get a list of unspent transactions in the address provided.
        """
        return BitcoinThread.request_blockr_json( "address/unspent/%s" % ",".join( addresses ), testnet )
    
    def commitTo(self, testnet, commit_address, private_key):
        """
        Commit to some address on the blockchain
        """
        # Check if we have the keys for the BM address
        public_key = highlevelcrypto.privToPub( private_key.encode('hex') ).decode('hex')
        fromAddress = self.getAddress( testnet, public_key )
        
        result = self.getUnspentTransactions( testnet, [fromAddress] )
        if not 'unspent' in result or len( result['unspent'] ) == 0:
            log_debug( "commitTo: No unspent TXs (%s)" % ( fromAddress ) )
            return False   
        
        unspent_txs = result['unspent']
        # filter for those with an amount >= minimum amount
        unspent_txs = filter( lambda tx: float( tx['amount'] ) > BitcoinThread.BTC_UNSPENT_MIN_AVAILABLE, unspent_txs )
        if len( unspent_txs ) == 0:
            log_debug( "commitTo: No unspent TXs >= %d (%s, %s)" % ( BitcoinThread.BTC_UNSPENT_MIN_AVAILABLE, fromAddress, result['unspent'] ) )
            return False
        
        # Find random unspent with an amount >= 0.00010 mBTC
        random.shuffle( unspent_txs )
        
        while len( unspent_txs ) > 0:
            tx = unspent_txs.pop( 0 )
            log_debug( "Trying unspent tx: %s" % tx )
            
            amount = float( tx['amount'] )

            amount_satoshis = int( amount * 100000000 )
            change_satoshis = amount_satoshis - BitcoinThread.SATOSHI_COMMITMENT_AMOUNT - BitcoinThread.SATOSHI_TRANSACTION_FEE
            
            # Code in bitcoin.mktx separates the input string into tx=input[:64] and n=input[65:]
            input_tx = "%s %d" % ( tx['tx'], tx['n'] )
            
            commit_payable = { "address": commit_address, "value": BitcoinThread.SATOSHI_COMMITMENT_AMOUNT }
            change_payable = { "address": fromAddress, "value": change_satoshis }
            
            tx = bitcoin.mktx( [input_tx], [ commit_payable, change_payable ] )
            
            signed_tx = bitcoin.sign(tx, 0, private_key )
            
            log_debug( "Pushing tx: %s" % bitcoin.deserialize( tx ) )
            
            if testnet:
                try:
                    result = json.loads( bitcoin.blockr_pushtx(signed_tx, 'testnet') )
                except Exception, e:
                    
                    # If we get {"status":"fail","data":"Could not push your transaction!","code":500,"message":"Did you sign your transaction?"}
                    # in an exception here, it probably means that the referenced inputs in our transaction have been spent in the meantime.
                    try:
                        e_obj = json.loads( e.message )
                        if e_obj["data"] == "Could not push your transaction!":
                            from debug import logger
                            log_warn( "Couldn't push transaction. Sometimes this is because the referenced inputs have been spent in the meantime, %s" % e_obj )
                            # Continue to try the next unspent tx
                            
                            continue
                        else:
                            log_warn( e )
                    except:
                        log_warn( e )
                        
                return 'status' in result and result['status'] == "success"
            
            else: # if not testnet
                # I had problems pushing non-testnet transactions to blockr.io,
                # so we're using blockchain.info for this, and that works fine.
                try:
                    result = bitcoin.pushtx( signed_tx )
                    if result.lower() == "transaction submitted":
                        log_debug( "Committed to %s" % commit_address )
                        return True
                    else:
                        log_warn( "Transaction push fail: %s" % ( result, ) )
                except Exception, e:
                    log_warn( "Transaction push exception: %s" % ( e, ) )
                continue
        
        log_debug( "commitTo: Exhausted all %d unspent_txs!" % ( len( result['unspent'] ) ) )
        return False
    
    def check_timestamp_alarms(self):
        """
        This function checks if any of the timestamp alarms are overdue, meaning that they
        should be called.
        It checks if the timestamps are "definitively passed", as per the functionality of
        getAdjustedBlockTimestamp(testnet, timestamp), and calls the callbacks of those who are.
        """
        def __check( testnet, alarms ):
            if not any( alarms ):
                return
            
            adjusted_timestamp, block_no = self.getAdjustedBlockTimestamp(testnet)
            log_debug( "Latest adjusted timestamp %sis block %d: %s" % ( "on testnet " if testnet else "", block_no, time.strftime( '%c', time.gmtime(adjusted_timestamp) ) ) )

            for alarm in alarms:
                # Update each alarm with last check time (local time)
                # and adjusted timestamp
                alarm.time_last_check = int( time.time() )
                alarm.last_adjusted_timestamp = adjusted_timestamp
                
            
            while len( alarms ) > 0:
                
                # Get earliest timestamp (list is sorted)
                alarm = alarms[0]
                
                if adjusted_timestamp < alarm.timestamp:
                    # If earliest timestamp isn't reached, just leave already...
                    return
                
                alarms.remove( alarm )
                if alarm in self.timestamp_alarms:
                    self.timestamp_alarms.remove( alarm )
                alarm.callback( adjusted_timestamp, block_no )
                
        regular_alarms = [ alarm for alarm in self.timestamp_alarms if not alarm.testnet ]
        testnet_alarms = [ alarm for alarm in self.timestamp_alarms if alarm.testnet ]
        __check( False, regular_alarms )
        __check( True, testnet_alarms )

        self.compute_next_timestamp_check()

    def compute_next_timestamp_check(self):
        if len( self.timestamp_alarms ) == 0:
            self.next_timestamp_check = None
        else:
            """
            We'll take the earliest testnet and non-testnet alarms,
            and check how far the last adjusted timestamp was from
            the alarm timestamp.
            The one with the shortest amount of time to the alarm timestamp
            is used to calculate the time for the next check,
            which we'll simply calculate as local time until the alarm timestamp
            times the ratio, but at least the minimum delay
            """
            regular_alarms = [ alarm for alarm in self.timestamp_alarms if not alarm.testnet ]
            testnet_alarms = [ alarm for alarm in self.timestamp_alarms if alarm.testnet ]
            
            last_adjusted_timestamp = None
            
            log_debug( "compute_next_check %d %d" % ( len( regular_alarms ), len( testnet_alarms ) ) )
            
            seconds_to_wait = None
            if any( regular_alarms ):
                al = regular_alarms[0]
                seconds = self.__estimate_time_until_adjusted_timestamp( al.timestamp, 
                                                                         BitcoinThread.get_latest_adjusted_timestamp(False)[1] )
                seconds_to_wait = seconds
                log_debug( "regular %d" % seconds_to_wait )
            if any( testnet_alarms ):
                al = testnet_alarms[0]
                
                seconds = self.__estimate_time_until_adjusted_timestamp( al.timestamp, 
                                                                         BitcoinThread.get_latest_adjusted_timestamp(True)[1] )
                if seconds_to_wait is None:
                    seconds_to_wait = seconds
                else:
                    seconds_to_wait = min( seconds, seconds_to_wait )
                log_debug( "testnet %d (%d)" % ( seconds_to_wait, seconds ) )
                
            self.next_timestamp_check = max( time.time() + int( seconds_to_wait * BitcoinThread.TIMESTAMP_ALARM_EXPECTED_WAIT_RATIO ),
                                             time.time() + BitcoinThread.MINIMUM_ALARM_CHECK_DELAY_SECONDS )
        
            log_debug( "Current time: %s" % time.strftime( '%c', time.gmtime( time.time() ) ) )
            log_debug( "Expected time for %s: %d" % ( time.strftime( '%c', time.gmtime( time.time() +seconds_to_wait ) ), seconds_to_wait ) )
            log_debug( "Next check is %s" % time.strftime( '%c', time.gmtime(self.next_timestamp_check )) )
            
    def __estimate_blocks_until_adjusted_timestamp(self, adjusted_timestamp, current_adjusted_timestamp):
        if current_adjusted_timestamp > adjusted_timestamp:
            return 0
        
        estimated_time = adjusted_timestamp - current_adjusted_timestamp
        return 1 + estimated_time / BitcoinThread.BITCOIN_AVERAGE_BLOCK_TIME_SECONDS 
        
    def __estimate_time_until_adjusted_timestamp(self, adjusted_timestamp, current_adjusted_timestamp):
        return BitcoinThread.BITCOIN_AVERAGE_BLOCK_TIME_SECONDS * self.__estimate_blocks_until_adjusted_timestamp(adjusted_timestamp, current_adjusted_timestamp)
            
    def estimate_time_until_timestamp_alarm(self, timestamp, n):
        matching_alarms = filter( lambda a: a.timestamp == timestamp, self.timestamp_alarms )
        if matching_alarms == []:
            return BitcoinThread.estimate_time_for_blocks_after(timestamp, n)
        elif len( matching_alarms ) > 1:
            # If there are more than one alarm with the same timestamp,
            # use the one with the highest n.
            alarm = sorted( matching_alarms, key=lambda alarm: alarm.n, reverse=True )
        else:
            alarm = matching_alarms[0]
            
        if alarm.time_last_check is None or alarm.blocks_missing_last_check is None:
            return BitcoinThread.estimate_time_for_blocks_after(timestamp, n)

        return BitcoinThread.estimate_time_for_blocks_after(alarm.time_last_check, alarm.blocks_missing_last_check)
            
    @staticmethod
    def estimate_time_for_blocks_after(timestamp, blocks_after):
        """
        Estimate timestamp. Timestamp input and output are seconds, not millis
        """
        return timestamp + ( blocks_after - 0.5 ) * BitcoinThread.BITCOIN_AVERAGE_BLOCK_TIME_SECONDS
            
    @staticmethod
    def request_blockr_json(path, testnet):
        """
        Blockr uses JSend specification for JSON object format
        (http://labs.omniti.com/labs/jsend)
        """
        api_base_url = BitcoinThread.BLOCKR_API_BASE_URL_TESTNET if testnet else BitcoinThread.BLOCKR_API_BASE_URL
        url = "%s%s" % ( api_base_url, path )
        log_debug( "HTTP GET %s" % url )
        try:
            obj = json.load(urllib2.urlopen(url) )
            if obj["status"] == "success":
                return obj["data"]
        except urllib2.HTTPError, urllib2.URLError:
            pass
        return None      
    
    def test(self):
        self.daemon = False
        self.start()
        def gen( testnet ):
            def cc( adjusted_timestamp, block_no ):
                print "*************** %s (%s): BLOCK NO %d: %s" % ( time.strftime('%c'), testnet, block_no, time.strftime('%c', time.gmtime(adjusted_timestamp)) )
            return cc
            
        BitcoinThread.enqueue( "test", "setTimestampAlarm", [ False, time.time()+1800 ], gen( False ) )  
        #BitcoinThread.enqueue( "test", "setTimestampAlarm", [ True, time.time() ], gen( True ) )  

class TimestampAlarm:
    def __init__(self, caller, testnet, timestamp, callback, time_last_check=None, last_adjusted_timestamp=None ):
        self.caller = caller
        self.testnet = testnet
        self.timestamp = timestamp
        self.callback = callback
        self.time_last_check = time_last_check
        self.last_adjusted_timestamp = last_adjusted_timestamp
        
    def __str__(self):
        return "TimestampAlarm<test:%s,time:%s>" % ( self.testnet, time.strftime( '%c', time.gmtime( self.timestamp ) ) )

def log_debug(msg):
    if DEBUG:
        logger.debug( "BitcoinThread> %s" % ( msg, ) )
def log_warn(msg):
    logger.warn( "BitcoinThread> %s" % ( msg, ) )
    
def test():
    t = BitcoinThread()
    t.daemon = True # Ensure that this thread exits when the main thread does
    t.start()

    assert t.getAddress( False, "myContent" ) == '17mCCPEnSB3vfZdy44uqqbgUG9fKB75wzZ'
    assert t.getAddress( False, "myOtherContent" ) == '1KdJGBjch3w8eXiwR3hxwqom3bfWHMrrvZ'
    assert t.getAddress( True,  "myContent" ) == 'mnH9VSKmFCVBSg7amdtDfWto89G26MNwbF'
    assert t.getAddress( True,  "myOtherContent" ) == 'mz9FZEpbW5NPReCZ8cgLmm25ubGDDiSsGw'
    
    assert '13QNcmJW8SmycXstccPJbBGrnQUEAmpjnm' == t.getCorrespondingAddress( False, None, pubSigningKey='\x83\xda\xbd\xbcx\xc9\x87\x9e\x89\x07\xec\x90\x1d\xceb\xef\xd0\xd7\xe8\xd3\xac\xc8\x92\xbc\x87O\x1e\xab\x89@Y)' )
    assert '1BAcePUqDtxWfWDE9MxTVnjfeCHnRm1uPE' == t.getCorrespondingAddress( False, None, pubSigningKey='\xc4\xb8\xa6\x19\xa1\xacl\xf7F\xb44\x01\xfa\xed\x05^p\x02%\xae7R\xeb|\xbdT\xb42L\xce\xa9\x89' )
    assert 'mhvKupPUwUDEPeMWLBMgR6VBeQ4w4urnFz' == t.getCorrespondingAddress( True,  None, pubSigningKey='\x83\xda\xbd\xbcx\xc9\x87\x9e\x89\x07\xec\x90\x1d\xceb\xef\xd0\xd7\xe8\xd3\xac\xc8\x92\xbc\x87O\x1e\xab\x89@Y)' )
    assert 'mqgZwSZp2vPmScgqrvvqKhwzWBtVNR8qfz' == t.getCorrespondingAddress( True,  None, pubSigningKey='\xc4\xb8\xa6\x19\xa1\xacl\xf7F\xb44\x01\xfa\xed\x05^p\x02%\xae7R\xeb|\xbdT\xb42L\xce\xa9\x89' )
    
    assert t.getFirstSeen( False, '1MMLLPTactnE2yiJv31kTB12j8eDyLHmm6' ) == 1412229173
    assert t.getFirstSeen( True,  'mfhG4UDt1ZXzEGpsDvWrFkZep7gKtUEVfZ' ) == 1404847254 
    
    import sys
    sys.exit(0)
    
if __name__ == "__main__":
    t = BitcoinThread()
    adjusted_timestamp, block_no = t.getAdjustedBlockTimestamp( False )
    print "Adjusted: %s, block_no: %d" % ( time.strftime( '%c', time.gmtime( adjusted_timestamp ) ), block_no )
    #block_no = t.getFirstBlockWithAdjustedTimestamp( False, adjusted_timestamp )
    #print "Block no: %d" % block_no
    #print "Again: %s" % ( time.strftime( '%c', time.gmtime( t.getAdjustedBlockTimestamp( False, block_no )[0] ) ) )
    #t.test()
    
     # Address 1H89HHurwmYnkfDyiNYxUfZx2oFcuZi2La
    #private_keyWIF = "5KTmQzrMhMjcgcpTdy6ZjFk7RjA6oPyuJTArG3HotpqPoZh4atk"
    #private_key = shared.decodeWalletImportFormat( private_keyWIF )
    #t.commitTo( False, "12XCmJCDTkVv6Z8TGtu73MjDjbHqoVTuNs", private_key)
