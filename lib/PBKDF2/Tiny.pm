use strict;
use warnings;

package PBKDF2::Tiny;
# ABSTRACT: Minimalist PBKDF2 (RFC 2898) with HMAC-SHA1 or HMAC-SHA2

our $VERSION = '0.003';

use Carp ();
use Exporter 5.57 qw/import/;

our @EXPORT_OK = qw/derive derive_hex verify verify_hex/;

my ( $BACKEND, $LOAD_ERR );
for my $mod (qw/Digest::SHA Digest::SHA::PurePerl/) {
    $BACKEND = $mod, last if eval "require $mod; 1";
    $LOAD_ERR ||= $@;
}
die $LOAD_ERR if !$BACKEND;

#--------------------------------------------------------------------------#
# constants and lookup tables
#--------------------------------------------------------------------------#

# function coderef placeholder, block size in bytes, digest size in bytes
my %DIGEST_TYPES = (
    'SHA-1'   => [ undef, 64,  20 ],
    'SHA-224' => [ undef, 64,  28 ],
    'SHA-256' => [ undef, 64,  32 ],
    'SHA-384' => [ undef, 128, 48 ],
    'SHA-512' => [ undef, 128, 64 ],
);

for my $type ( keys %DIGEST_TYPES ) {
    no strict 'refs';
    ( my $name = lc $type ) =~ s{-}{};
    $DIGEST_TYPES{$type}[0] = \&{"$BACKEND\::$name"};
}

my %INT = map { $_ => pack( "N", $_ ) } 1 .. 16;

#--------------------------------------------------------------------------#
# public functions
#--------------------------------------------------------------------------#

=func derive

    $dk = derive( $type, $password, $salt, $iterations, $dk_length )

The C<derive> function outputs a binary string with the derived key.
The first argument indicates the digest function to use.  It must be one
of: SHA-1, SHA-224, SHA-256, SHA-384, or SHA-512.

If a password or salt are not provided, they default to the empty string, so
don't do that!  L<RFC 2898
recommends|https://tools.ietf.org/html/rfc2898#section-4.1> a random salt of at
least 8 octets.  If you need a cryptographically strong salt, consider
L<Crypt::URandom>.

The number of iterations defaults to 1000 if not provided.  If the derived
key length is not provided, it defaults to the output size of the digest
function.

=cut

sub derive {
    my ( $type, $passwd, $salt, $iterations, $dk_length ) = @_;

    my ( $digester, $block_size, $digest_length ) = digest_fcn($type);

    $passwd = '' unless defined $passwd;
    $salt   = '' unless defined $salt;
    $iterations ||= 1000;
    $dk_length  ||= $digest_length;

    my $key = ( length($passwd) > $block_size ) ? $digester->($passwd) : $passwd;
    my $passes = int( $dk_length / $digest_length );
    $passes++ if $dk_length % $digest_length; # need part of an extra pass

    my $dk = "";
    for my $i ( 1 .. $passes ) {
        $INT{$i} ||= pack( "N", $i );
        my $digest = my $result =
          "" . hmac( $salt . $INT{$i}, $key, $digester, $block_size );
        for my $iter ( 2 .. $iterations ) {
            $digest = hmac( $digest, $key, $digester, $block_size );
            $result ^= $digest;
        }
        $dk .= $result;
    }

    return substr( $dk, 0, $dk_length );
}

=func derive_hex

Works just like L</derive> but outputs a hex string.

=cut

sub derive_hex { unpack( "H*", &derive ) }

=func verify

    $bool = verify( $dk, $type, $password, $salt, $iterations, $dk_length );

The C<verify> function checks that a given derived key (in binary form) matches
the password and other parameters provided using a constant-time comparison
function.

The first parameter is the derived key to check.  The remaining parameters
are the same as for L</derive>.

=cut

sub verify {
    my ( $dk1, $type, $password, $salt, $iterations, $dk_length ) = @_;

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

=func verify_hex

Works just like L</verify> but the derived key must be a hex string (without a
leading "0x").

=cut

sub verify_hex {
    my $dk = pack( "H*", shift );
    return verify( $dk, @_ );
}

=func digest_fcn

    ($fcn, $block_size, $digest_length) = digest_fcn('SHA-1');
    $digest = $fcn->($data);

This function is used internally by PBKDF2::Tiny, but made available in case
it's useful to someone.

Given one of the valid digest types, it returns a function reference that
digests a string of data. It also returns block size and digest length for that
digest type.

=cut

sub digest_fcn {
    my ($type) = @_;

    Carp::croak("Digest function '$type' not supported")
      unless exists $DIGEST_TYPES{$type};

    return @{ $DIGEST_TYPES{$type} };
}

=func hmac

    $key = $digest_fcn->($key) if length($key) > $block_sizes;
    $hmac = hmac( $data, $key, $digest_fcn, $block_size );

This function is used internally by PBKDF2::Tiny, but made available in case
it's useful to someone.

The first two arguments are the data and key inputs to the HMAC function.
B<Note>: if the key is longer than the digest block size, it must be
preprocessed using the digesting function.

The third and fourth arguments must be a digesting code reference (from
L</digest_fcn>) and block size.

=cut

# hmac function adapted from Digest::HMAC by Graham Barr and Gisle Aas.
# Compared to that implementation, this *requires* a preprocessed
# key and block size, which makes iterative hmac slightly more efficient.
sub hmac {
    my ( $data, $key, $digest_func, $block_size ) = @_;

    my $k_ipad = $key ^ ( chr(0x36) x $block_size );
    my $k_opad = $key ^ ( chr(0x5c) x $block_size );

    &$digest_func( $k_opad, &$digest_func( $k_ipad, $data ) );
}

1;

=for Pod::Coverage

=head1 SYNOPSIS

    use PBKDF2::Tiny qw/derive verify/;

    my $dk = derive( 'SHA-1', $pass, $salt, $iters );

    if ( verify( $dk, 'SHA-1', $pass, $salt, $iters ) ) {
        # password is correct
    }

=head1 DESCRIPTION

This module provides an L<RFC 2898|https://tools.ietf.org/html/rfc2898>
compliant PBKDF2 implementation using HMAC-SHA1 or HMAC-SHA2 in under 100 lines
of code.  If you are using Perl 5.10 or later, it uses only core Perl modules.
If you are on an earlier version of Perl, you need L<Digest::SHA> or
L<Digest::SHA::PurePerl>.

=head1 SEE ALSO

=for :list
* L<Crypt::PBKDF2>
* L<Digest::PBDKF2>

=cut

# vim: ts=4 sts=4 sw=4 et:
