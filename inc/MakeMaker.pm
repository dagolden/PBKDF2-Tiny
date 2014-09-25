# copied/adapted from Package::Stash
package inc::MakeMaker;
use Moose;

extends 'Dist::Zilla::Plugin::MakeMaker::Awesome';

with 'Dist::Zilla::Role::MetaProvider';

# XXX: this is pretty gross, it should be possible to clean this up later
around _build_MakeFile_PL_template => sub {
    my $orig = shift;
    my $self = shift;

    # can_run and can_cc copied from M::I
    my $helpers = <<'HELPERS';
use Config ();
use File::Spec ();
use Text::ParseWords ();

# check if we can run some command
sub can_run {
        my ($cmd) = @_;

        my $_cmd = $cmd;
        return $_cmd if (-x $_cmd or $_cmd = MM->maybe_command($_cmd));

        for my $dir ((split /$Config::Config{path_sep}/, $ENV{PATH}), '.') {
                next if $dir eq '';
                my $abs = File::Spec->catfile($dir, $_[0]);
                return $abs if (-x $abs or $abs = MM->maybe_command($abs));
        }

        return;
}

# can we locate a (the) C compiler
sub can_cc {
        my @chunks = split(/ /, $Config::Config{cc}) or return;

        # $Config{cc} may contain args; try to find out the program part
        while (@chunks) {
                return can_run("@chunks") || (pop(@chunks), next);
        }

        return;
}

# XXX this is gross, but apparently it's the least gross option?
sub parse_args {
    my $tmp = {};
    # copied from EUMM
    ExtUtils::MakeMaker::parse_args(
        $tmp,
        Text::ParseWords::shellwords($ENV{PERL_MM_OPT} || ''),
        @ARGV,
    );
    return $tmp->{ARGS} || {};
}
HELPERS

    my $fixup_prereqs = <<PREREQS;
if ( \$] < 5.010 ) {
    if ( !parse_args()->{PUREPERL_ONLY} && can_cc() ) {
        \$WriteMakefileArgs{PREREQ_PM}{'Devel::SHA'} = 0;
    }
    else {
        \$WriteMakefileArgs{PREREQ_PM}{'Devel::SHA::PurePerl'} = 0;
    }
}
PREREQS

    my $template = $self->$orig(@_);
    $template =~ s/(WriteMakefile\()/$fixup_prereqs\n$1/;
    $template .= $helpers;

    return $template;
};

after register_prereqs => sub {
    my $self = shift;
    $self->zilla->register_prereqs(
        { phase => 'configure' },
        'Config'           => 0,
        'File::Spec'       => 0,
        'Text::ParseWords' => 0,
    );
};

sub metadata { return +{ dynamic_config => 1 } }

__PACKAGE__->meta->make_immutable;
no Moose;

1;
