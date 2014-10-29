'''
Created on 27/09/2014

@author: Jesper
'''

import datetime

class ConsensusHelper:
    @staticmethod
    def unix_time(dt):
        """
        Convert a datetime.datetime instance to unix timestamp
        """
        epoch = datetime.datetime.utcfromtimestamp(0)
        delta = dt - epoch
        return delta.total_seconds()
    
    @staticmethod
    def parse_utc_timestamp(ts):
        """
        Parse a UTC timestamp string to unix timestamp
        Format: "2014-10-03T14:18:50Z"
        """
        return ConsensusHelper.unix_time( datetime.datetime.strptime(ts, '%Y-%m-%dT%H:%M:%SZ') )
