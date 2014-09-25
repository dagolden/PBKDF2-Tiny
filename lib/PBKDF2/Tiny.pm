use strict;
use warnings;

package PBKDF2::Tiny;
# ABSTRACT: Minimalist PBKDF2 (RFC 2898) with HMAC and choice of digest function
# VERSION

use Carp   ();
use Digest ();
use Exporter 5.57 qw/import/;

our @EXPORT_OK = qw/derive derive_hex verify verify_hex/;

#--------------------------------------------------------------------------#
# constants and lookup tables
#--------------------------------------------------------------------------#

my %BLOCK_SIZE_BITS = (
    'MD5'     => 512,
    'SHA-1'   => 512,
    'SHA-224' => 512,
    'SHA-256' => 512,
    'SHA-384' => 1024,
    'SHA-512' => 1024,
);

my %BLOCK_SIZE = map { $_ => $BLOCK_SIZE_BITS{$_} / 8 } keys %BLOCK_SIZE_BITS;

my %INT = map { $_ => pack( "N", $_ ) } 1 .. 16;

my ( %HASHERS, %HASH_LENGTH );

#--------------------------------------------------------------------------#
# public functions
#--------------------------------------------------------------------------#

sub derive {
    my ( $type, $passwd, $salt, $iterations, $dk_length ) = @_;

    my $hasher      = $HASHERS{$type} || _init_hasher_fcn($type);
    my $block_size  = $BLOCK_SIZE{$type};
    my $hash_length = $HASH_LENGTH{$type};

    $passwd = '' unless defined $passwd;
    $salt   = '' unless defined $salt;
    $iterations ||= 1000;
    $dk_length  ||= $hash_length;

    my $key = ( length($passwd) > $block_size ) ? $hasher->($passwd) : $passwd;
    my $passes = int( $dk_length / $hash_length );
    $passes++ if $dk_length % $hash_length; # need part of an extra pass

    my $dk = "";
    for my $i ( 1 .. $passes ) {
        $INT{$i} ||= pack( "N", $i );
        my $hash = my $result = "" . _hmac( $salt . $INT{$i}, $key, $hasher, $block_size );
        for my $iter ( 2 .. $iterations ) {
            $hash = _hmac( $hash, $key, $hasher, $block_size );
            $result ^= $hash;
        }
        $dk .= $result;
    }

    return substr( $dk, 0, $dk_length );
}

sub derive_hex { unpack( "H*", &derive ) }

sub verify {
    my ( $type, $dk1, $password, $salt, $iterations, $dk_length ) = @_;

    my $dk2 = derive( $type, $password, $salt, $iterations, $dk_length );

    # shortcut if input dk is the wrong length entirely; this is not
    # constant time, but this doesn't really give much away as
    # the keys are of different types anyway

    return unless length($dk1) == length($dk2);

    # if lengths match, do constant time comparison to avoid timing attacks
    my $match = 1;
    for my $offset ( 0 .. $dk_length ) {
        $match &= ( substr( $dk1, $offset, 1 ) eq substr( $dk2, $offset, 1 ) ) ? 1 : 0;
    }

    return $match;
}

sub verify_hex {
    my ( $type, $dk1, $password, $salt, $iterations, $dk_length ) = @_;
    $dk1 = pack( "H*", $dk1 );
    return verify( $type, $dk1, $password, $salt, $iterations, $dk_length );
}

#--------------------------------------------------------------------------#
# private functions
#--------------------------------------------------------------------------#

# _hmac function adapted from Digest::HMAC by Graham Barr and Gisle Aas
sub _hmac {
    my ( $data, $key, $hash_func, $block_size ) = @_;

    my $k_ipad = $key ^ ( chr(0x36) x $block_size );
    my $k_opad = $key ^ ( chr(0x5c) x $block_size );

    &$hash_func( $k_opad, &$hash_func( $k_ipad, $data ) );
}

sub _init_hasher_fcn {
    my ($type) = @_;
    unless ( $BLOCK_SIZE{$type} ) {
        Carp::croak("Hash function '$type' not supported");
    }
    unless ( eval { Digest->new($type) } ) {
        ( my $err = $@ ) =~ s{ at \S+ line \d+.*}{};
        Carp::croak("Hash function '$type' not available: $err");
    }
    my $hasher = $HASHERS{$type} = sub { Digest->new($type)->add(@_)->digest };
    $HASH_LENGTH{$type} = length( $hasher->("0") );
    return $hasher;
}

1;

=for Pod::Coverage BUILD

=head1 SYNOPSIS

    use PBKDF2::Tiny qw/derive verify/;

    my $dk = derive( 'SHA-1', $pass, $salt, $iters );

    if ( verify( 'SHA-1', $dk, $pass, $salt, $iters ) ) {
        # password is correct
    }

=head1 DESCRIPTION

This module provides an RFC 2898 compliant PBKDF2 implmentation using HMAC and
several possible digest functions in under 100 lines of code.

=head1 SEE ALSO

=for :list
* L<Crypt::PBKDF2>
* L<Digest::PBDKF2>

=cut

# vim: ts=4 sts=4 sw=4 et:
