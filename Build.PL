use strict;
use warnings;
use Module::Build;

my $builder = Module::Build->new(
    module_name         => 'winny_scanner',
    license             => 'perl',
    dist_author         => 'Masanori Hara <massa.hara at gmail.com>',
    dist_version_from   => 'script/winny_scanner',
    requires => {
        'Test::More' => 0,
        'Crypt::RC4' => 0,
    },
    script_files =>  [
        'script/winny_scanner',
    ],
    add_to_cleanup      => [ 'winny_scanner-*' ],
);

$builder->create_build_script();
