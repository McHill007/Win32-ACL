package Win32::ACL;
require Exporter;


@ISA    = qw( Exporter );
@EXPORT = qw(  );  

# +----------------------------------------------------------------------+
# |                         USED PERL MODULES                            |
# +----------------------------------------------------------------------+
use strict ;
use warnings;
use Carp qw();
use Win32::API;
use Data::Dumper;
use Win32::Security::ACL;
use Win32::Security::Raw;
use Win32::Security::NamedObject;
use Win32::Security::SID;
use once;
no autovivification; 

# +----------------------------------------------------------------------+
# |                        PREDEFINED VALUES                             
# +----------------------------------------------------------------------+
use constant DIRECTORY_SEPARATOR => "\\";


use constant TOKEN_ADJUST_PRIVILEGES 	=> 0x0020 ;
use constant TOKEN_QUERY             	=> 0x0008  ;
use constant SE_SECURITY_PRIVILIGE 		=> 'SeSecurityPrivilege' ;
use constant SE_PRIVILEGE_ENABLED  		=>  2  ;

my $kernel32 = 'kernel32.dll';
my $advapi32 = 'advapi32.dll';
my $CloseHandle = new Win32::API($kernel32,'CloseHandle','N', 'I') || die;
my $OpenProcessToken      = new Win32::API($advapi32,'OpenProcessToken','NNP', 'I' ) || die $^E;
my $LookupPrivilegeValue  = new Win32::API($advapi32,'LookupPrivilegeValue','PPP', 'I') || die $^E;
my $AdjustTokenPrivileges = new Win32::API($advapi32,'AdjustTokenPrivileges','NIPNPP', 'I') || die $^E;


ONCE{__setPrivilige()};


# +----------------------------------------------------------------------+
# | Function: new
# +----------------------------------------------------------------------+
# | Description: Class constructor
# +----------------------------------------------------------------------+
sub new 
{
	my $class = shift;
	my $self = {};
	bless $self, $class;
	return $self;
}



# +----------------------------------------------------------------------+
# | Function: getDACL
# +----------------------------------------------------------------------+
# | Description: Get DACL information
# +----------------------------------------------------------------------+ 
sub getDACL
{
	my $self = shift;
	my $IOobj = shift ;
	my @DACLS = () ;

	Carp::croak("Win32::ACL::getSACL - No filename/directory specified.") if ( ! $IOobj ) ;
	Carp::croak("Win32::ACL::getSACL - File or Directory $IOobj does not exist.") if ( !-f $IOobj && !-d $IOobj ) ;

	my $acl = Win32::Security::NamedObject->new('SE_FILE_OBJECT', $IOobj);
	return ( @DACLS ) unless ( $acl ) ;
	my $dacl = $acl->dacl();
	$dacl->dump() ;
	foreach my $daclitem ( $dacl->aces )
	{
		my %DACLInformation = (
		'sid' 		=>  Win32::Security::SID::ConvertSidToStringSid( $daclitem->sid ),
		'trustee' 	=>  $daclitem->trustee  ,
		'aceType' 	=>  $daclitem->aceType  ,
		'aceFlags' 	=>  $daclitem->explainAceFlags  ,
		'aceMask' 	=>  $daclitem->explainAccessMask  ) ;
		push @DACLS,  \%DACLInformation ;
	}
	
	
	return(@DACLS) ;
	
	
}



# +----------------------------------------------------------------------+
# | Function: getSACL
# +----------------------------------------------------------------------+
# | Description: Get SACL information
# +----------------------------------------------------------------------+ 
sub getSACL
{
	my $self = shift;
	my $IOobj = shift ;
	my @SACLS = () ;	
	
	Carp::croak("Win32::ACL::getSACL - No filename/directory specified.") if ( ! $IOobj ) ;
	Carp::croak("Win32::ACL::getSACL - File or Directory $IOobj does not exist.") if ( !-f $IOobj && !-d $IOobj ) ;
	

	
	my($ppsidOwner, $ppsidGroup, $ppDacl, $ppSacl, $ppSecurityDescriptor) =
	Win32::Security::Raw::GetNamedSecurityInfo($IOobj, 'SE_FILE_OBJECT' , 'SACL_SECURITY_INFORMATION'); 
	return ( @SACLS ) unless ( $ppSacl ) ;
	my($AceCount, $AclBytesInUse, $AclBytesFree) = Win32::Security::Raw::GetAclInformation($ppSacl, 'AclSizeInformation');
	my $sacl = Win32::Security::ACL::SE_FILE_OBJECT->new(Win32::Security::Raw::CopyMemory_Read($ppSacl, $AclBytesInUse));
	
	$sacl->dump();
	
	foreach my $saclitem ( $sacl->aces )
	{
		my %SACLInformation = (
		'sid' 		=>  Win32::Security::SID::ConvertSidToStringSid( $saclitem->sid ),
		'trustee' 	=>  $saclitem->trustee  ,
		'aceType' 	=>  $saclitem->aceType  ,
		'aceFlags' 	=>  $saclitem->explainAceFlags  ,
		'aceMask' 	=>  $saclitem->explainAccessMask  ) ;
		push @SACLS,  \%SACLInformation ;
	}	
	return ( @SACLS );
}









# +----------------------------------------------------------------------+
# | Function: setPrivilige
# +----------------------------------------------------------------------+
# | Description: Once set required privilige
# +----------------------------------------------------------------------+ 
sub __setPrivilige 
{
	my $phToken = pack("L", 0);
	if($OpenProcessToken->Call(Win32::Security::Raw::GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,$phToken)) 
	{
		my $hToken = unpack("L", $phToken);
		my $pLuid = pack("Ll", 0, 0);
		if($LookupPrivilegeValue->Call("\x00\x00", SE_SECURITY_PRIVILIGE, $pLuid))
		{
			my $pPrivStruct = pack("LLlL",1,unpack("Ll", $pLuid),((1)? SE_PRIVILEGE_ENABLED : 0));
			return(0 != $AdjustTokenPrivileges->Call($hToken,0,$pPrivStruct,length($pPrivStruct),0, 0));
		}		
		$CloseHandle->Call($hToken);
	}
}






































1;
