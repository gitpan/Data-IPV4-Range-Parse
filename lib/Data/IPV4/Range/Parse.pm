package Data::IPV4::Range::Parse;

use strict;
use warnings;
use Carp qw(croak);
use vars qw(@ISA %EXPORT_TAGS @EXPORT_OK $VERSION @EXPORT);

$VERSION = '1.04';

require Exporter;
@ISA = qw(Exporter);

%EXPORT_TAGS = ( 'ALL'=>\@EXPORT_OK );

@EXPORT_OK=qw();

push @EXPORT_OK,qw(
 ALL_BITS
 MAX_CIDR
 MIN_CIDR
);
$EXPORT_TAGS{CONSTANTS}=[qw(
 ALL_BITS
 MAX_CIDR
 MIN_CIDR
)];
use constant ALL_BITS=>0xffffffff;
use constant MAX_CIDR=>32;
use constant MIN_CIDR=>0;

push @EXPORT_OK,
  qw(
    int_to_ip
    ip_to_int
  );

$EXPORT_TAGS{PARSE_IP}=[qw(
    int_to_ip
    ip_to_int
  )];

sub int_to_ip ($) { shift if $#_>0;join '.',unpack('C4',(pack('N',$_[0]))) }
sub ip_to_int ($) { shift if $#_>0;unpack('N',pack('C4',split(/\./,$_[0]))) }


push @EXPORT_OK,
  qw(
    sort_quad
    sort_notations
  );

$EXPORT_TAGS{SORT}=[qw(
    sort_quad
    sort_notations
  )];
sub sort_quad ($$) {
  my ($ip_a,$ip_b)=@_;
  ip_to_int($ip_a) <=> ip_to_int($ip_b)
}

sub sort_notations ($$) {
  my ($a_start,$a_end,$b_start,$b_end)=map { auto_parse_ipv4_range($_) } @_;
  croak 'cannot parse notation a or b'
    unless defined($b_end);
  my $ab_cmp=($a_start<=>$b_start);
  return $ab_cmp if $ab_cmp!=0;
  $a_end <=> $b_end
}

push @EXPORT_OK,
  qw(
  broadcast_int
  base_int
  size_from_mask
  hostmask
  cidr_to_int
);
$EXPORT_TAGS{COMPUTE_FROM_INT}=[
  qw(
  broadcast_int
  base_int
  size_from_mask
  hostmask
  cidr_to_int
  )
];
sub broadcast_int ($$) { shift if $#_>1;base_int($_[0],$_[1]) + hostmask($_[1]) }
sub base_int ($$) { shift if $#_>1;$_[0] & $_[1] }
sub size_from_mask ($) { shift if $#_>0;1 + hostmask($_[0] ) }
sub hostmask ($) { shift if $#_>0;ALL_BITS & (~(ALL_BITS & $_[0])) }
sub cidr_to_int ($) {
  shift if $#_>0;
  my ($cidr)=@_;
  my $shift=MAX_CIDR -$cidr;
  return undef unless defined($cidr);
  return undef unless $cidr=~ /^\d{1,2}$/s;
  return undef if $cidr>MAX_CIDR or $cidr<MIN_CIDR;
  return 0 if $shift==MAX_CIDR;
  ALL_BITS & (ALL_BITS << $shift)
}
$EXPORT_TAGS{PARSE_RANGE}=[];
push @EXPORT_OK,'parse_ipv4_cidr';
push @{$EXPORT_TAGS{PARSE_RANGE}},'parse_ipv4_cidr';

sub parse_ipv4_cidr {
  my $notation=$_[$#_];
  $notation=~ s/(^\s+|\s+$)//g;
  return () 
    unless($notation=~ /
      ^\d{1,3}(\.\d{1,3}){0,3}
      \s*\/\s*
      \d{1,3}(\.\d{1,3}){0,3}$
    /x);
  my ($ip,$mask)=split /\s*\/\s*/,$notation;
  my $ip_int=ip_to_int($ip);
  my $mask_int;

  if($mask=~ /\./) {
    # we know its quad notation
    $mask_int=ip_to_int($mask);
  } elsif($mask>=MIN_CIDR && $mask<=MAX_CIDR) {
    $mask_int=cidr_to_int($mask);
  } else {
    $mask_int=ip_to_int($mask);
  }
  my $first_int=base_int($ip_int , $mask_int);
  my $last_int=broadcast_int( $first_int,$mask_int);

  ($first_int,$last_int)
}

push @EXPORT_OK,'parse_ipv4_range';
push @{$EXPORT_TAGS{PARSE_RANGE}},'parse_ipv4_range';

sub parse_ipv4_range {
  my $range=$_[$#_];
  return () unless defined($range);
  # lop off start and end spaces
  $range=~ s/(^\s+|\s+$)//g;

  return () unless $range=~ /
      ^\d{1,3}(\.\d{1,3}){0,3}
      \s*-\s*
      \d{1,3}(\.\d{1,3}){0,3}$
    /x;
  
  my ($start,$end)=split /\s*-\s*/,$range;
 ( ip_to_int($start) ,ip_to_int($end))
}

push @EXPORT_OK,'parse_ipv4_ip';
push @{$EXPORT_TAGS{PARSE_RANGE}},'parse_ipv4_ip';

sub parse_ipv4_ip {
  my $ip=$_[$#_];
  return () unless defined($ip);
  
  ( ip_to_int($ip) ,ip_to_int($ip))
}

push @EXPORT_OK,'auto_parse_ipv4_range';
push @{$EXPORT_TAGS{PARSE_RANGE}},'auto_parse_ipv4_range';
push @EXPORT,'auto_parse_ipv4_range';

sub auto_parse_ipv4_range {
  my $source=$_[$#_];
  return parse_ipv4_cidr($source) if $source=~ /\//;
  return parse_ipv4_range($source) if $source=~ /-/;
  return parse_ipv4_ip($source);
}


1;
__END__
