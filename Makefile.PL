use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'winny_scanner',
    AUTHOR              => 'Masanori Hara <massa.hara at gmail.com>',
    VERSION_FROM        => 'script/winny_scanner',
    ABSTRACT_FROM       => 'script/winny_scanner',
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
        'Crypt::RC4' => 0,
    },
    EXE_FILES =>  [
        'script/winny_scanner',
    ],
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'winny_scanner-*' },
);
