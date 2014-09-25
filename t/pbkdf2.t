use strict;
use warnings;
use Test::More 0.88;
use Test::FailWarnings;
binmode( Test::More->builder->$_, ":utf8" )
  for qw/output failure_output todo_output/;

use PBKDF2::Tiny qw/derive derive_hex verify verify_hex/;

#--------------------------------------------------------------------------#
# custom test function
#--------------------------------------------------------------------------#

sub is_hex {
    my ( $got, $exp, $label ) = @_;
    local $Test::Builder::Level = $Test::Builder::Level + 1;
    is( unpack( "H*", $got ), unpack( "H*", $exp ), $label );
}

#--------------------------------------------------------------------------#
# Test cases:
#
# Several PBKDF2 HMAC-SHA1 test cases from RFC 6070; other
# cases computed with Crypt::PBKDF2
#--------------------------------------------------------------------------#

my @cases = (
    {
        n => 'SHA-1 1 iter',
        a => 'SHA-1',
        p => 'password',
        s => 'salt',
        c => 1,
        l => 20,
        o => "0c 60 c8 0f 96 1f 0e 71 f3 a9 b5 24 af 60 12 06 2f e0 37 a6",
    },
    {
        n => 'SHA-1 2 iters',
        a => 'SHA-1',
        p => 'password',
        s => 'salt',
        c => 2,
        l => 20,
        o => "ea 6c 01 4d c7 2d 6f 8c cd 1e d9 2a ce 1d 41 f0 d8 de 89 57"
    },
    {
        n => 'SHA-1 3 iters',
        a => 'SHA-1',
        p => 'password',
        s => 'salt',
        c => 3,
        l => 20,
        o => "6b4e26125c25cf21ae35ead955f479ea2e71f6ff",
    },
    {
        n => 'SHA-1 4096 iters',
        a => 'SHA-1',
        p => 'password',
        s => 'salt',
        c => 4096,
        l => 20,
        o => "4b 00 79 01 b7 65 48 9a be ad 49 d9 26 f7 21 d0 65 a4 29 c1"
    },
);

#--------------------------------------------------------------------------#
# test runner
#--------------------------------------------------------------------------#

for my $c (@cases) {
    ( my $exp_hex = $c->{o} ) =~ s{ }{}g; # strip spaces
    my $exp = pack( "H*", $exp_hex );

    my $got = derive( @{$c}{qw/a p s c l/} );
    is_hex( $got, $exp, "$c->{n} (derive)" );

    my $got_hex = derive_hex( @{$c}{qw/a p s c l/} );
    is( $got_hex, $exp_hex, "$c->{n} (derive hex)" );

    ok( verify( $c->{a}, $exp, @{$c}{qw/p s c l/} ), "$c->{n} (verify)" );
    ok( verify_hex( $c->{a}, $exp_hex, @{$c}{qw/p s c l/} ), "$c->{n} (verify hex)" );
}

done_testing;

# COPYRIGHT
# vim: ts=4 sts=4 sw=4 et:
