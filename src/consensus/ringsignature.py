'''
Created on 08/05/2014

@author: Jesper
'''
from random import randint

from pyelliptic import arithmetic
from ec import curve as ec_curve, point as ec_point

class RingSignature:
    MAGIC_ID = "RINGSIGNATURE"
    CURVE_NAME = 'secp256k1'
    DEBUG = False

    @staticmethod
    def sign_message( message, pubkeys, private_key, signer_index ):
        key_count = len( pubkeys )
        
        curve = ec_curve.Curve( RingSignature.CURVE_NAME )
        
        # Retrieve all public keys and their coordinates
        public_keys = map( lambda x: RingSignature.pubkey_to_point( curve, x ), pubkeys )
        public_keys_coords = map( lambda point: (point.x, point.y), public_keys )
        
        # Make room for c_i, s_i, z'_i, and z''_i variables
        cs = [0] * key_count
        ss = [0] * key_count
        z_s = [0] * key_count
        z__s = [0] * key_count
        
        # Step 1
        public_keys_hash = curve.hash_to_field( "%s" % public_keys_coords )
        H = RingSignature.H2( curve, public_keys_coords )
        print "privkey: %s, %s, H: %s, %s" % ( type( private_key ), repr( private_key ), type( H ), repr( H ) )
        Y_tilde = private_key * H
    
        # Step 2
        u = randint( 0, curve.order )
        pi_plus_1 = (signer_index+1) % key_count
        cs[pi_plus_1] = RingSignature.H1( curve, public_keys_hash, Y_tilde, message,
                            u * curve.G, u * H )
    
        # Step 3
        for i in range( signer_index+1, key_count ) + range( signer_index ):
            ss[i] = randint( 0, curve.order )
            next_i = (i+1) % key_count
            z_s[i] = ss[i] * curve.G + cs[i] * public_keys[i]
            z__s[i] = ss[i] * H + cs[i] * Y_tilde
            cs[next_i] = RingSignature.H1( curve, public_keys_hash, Y_tilde, message, z_s[i], z__s[i] )
    
        # Step 4
        ss[signer_index] = ( u - private_key * cs[signer_index] ) % curve.order

        return ( cs[0], ss, Y_tilde )

    @staticmethod
    def verify_message(message, pubkeys, c_0, ss, Y_tilde):
        curve = ec_curve.Curve( RingSignature.CURVE_NAME )
        
        public_keys = map( lambda x: RingSignature.pubkey_to_point( curve, x ), pubkeys )
        public_keys_coords = map( lambda point: (point.x, point.y), public_keys )
    
        n = len( public_keys )
    
        cs = [c_0] + [0] * ( n - 1 )
        z_s = [0] * n
        z__s = [0] * n
    
        # Step 1
        public_keys_hash = curve.hash_to_field( "%s" % public_keys_coords )
        H = RingSignature.H2( curve, public_keys_coords )
        for i in range( n ):
            z_s[i] = ss[i] * curve.G + cs[i] * public_keys[i]
            z__s[i] = ss[i] * H + cs[i] * Y_tilde
            if i < n - 1:
                cs[i+1] = RingSignature.H1( curve, public_keys_hash, Y_tilde, message, z_s[i], z__s[i] )
    
        print "Verify: n: %d, len(z_s): %d, len(z__s): %d" % ( n, len(z_s), len( z__s) )
        H1_ver = RingSignature.H1( curve, public_keys_hash, Y_tilde, message, z_s[n-1], z__s[n-1] )
    
        return cs[0] == H1_ver
    
    @staticmethod
    def H2( curve, in_str ):
        """
        Hash the input as a string and return the hash as a point on the curve.
        """
        return curve.hash_to_point( "H2_salt%s" % in_str )
    
    @staticmethod
    def H1( curve, keys, Y_tilde, message, P1, P2):
        """
        The H1 function that hashes a lot of variables
        and returns the hash as an integer.
        """
        string_to_hash = "%s,%s,%s,%X,%X,%X,%X" % ( keys, Y_tilde, message,
                                                    P1.x, P1.y, P2.x, P2.y)
        return curve.hash_to_field( "H1_salt%s" % string_to_hash )
    
    @staticmethod
    def pubkey_to_point(curve, pubkey):
        assert len( pubkey ) == 64
        return ec_point.Point( curve,
                               x=arithmetic.decode( pubkey[:32], 256 ), 
                               y=arithmetic.decode( pubkey[32:], 256 ) )
        