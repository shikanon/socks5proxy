// Read-only Wi-Fi/en1 proxy settings. macOS only; does not grant permissions.
#import <Foundation/Foundation.h>
#import <SystemConfiguration/SystemConfiguration.h>
int main(int argc,const char *argv[]) {
 @autoreleasepool {
  if(argc!=3){fprintf(stderr,"Usage: proxy-settings snapshot|status snapshot.plist\n");return 2;}
  NSString *action=@(argv[1]),*path=@(argv[2]);
  SCPreferencesRef prefs=SCPreferencesCreate(NULL,CFSTR("Community PAC snapshot"),NULL);
  if(!prefs)return 3;
  CFArrayRef services=SCNetworkServiceCopyAll(prefs);
  SCNetworkProtocolRef protocol=NULL;
  for(id item in (__bridge NSArray*)services){
   SCNetworkServiceRef service=(__bridge SCNetworkServiceRef)item;
   NSString *name=(__bridge NSString*)SCNetworkServiceGetName(service);
   SCNetworkInterfaceRef interface=SCNetworkServiceGetInterface(service);
   NSString *device=(__bridge NSString*)SCNetworkInterfaceGetBSDName(interface);
   if([name isEqualToString:@"Wi-Fi"]&&[device isEqualToString:@"en1"]){protocol=SCNetworkServiceCopyProtocol(service,kSCNetworkProtocolTypeProxies);break;}
  }
  if(!protocol){fprintf(stderr,"Wi-Fi/en1 not found; no changes\n");return 4;}
  NSDictionary *current=(__bridge NSDictionary*)SCNetworkProtocolGetConfiguration(protocol);
  if(!current)return 4;
  BOOL ok=YES;
  if([action isEqualToString:@"snapshot"]){
   if([[NSFileManager defaultManager] fileExistsAtPath:path]){fprintf(stderr,"Snapshot exists; not overwriting\n");return 5;}
   NSData *data=[NSPropertyListSerialization dataWithPropertyList:current format:NSPropertyListXMLFormat_v1_0 options:0 error:nil];
   ok=[data writeToFile:path options:NSDataWritingAtomic error:nil];
  }else if([action isEqualToString:@"status"]){
   NSData *data=[NSJSONSerialization dataWithJSONObject:current options:NSJSONWritingPrettyPrinted error:nil];
   if(data)fwrite(data.bytes,1,data.length,stdout);puts("");
  }else return 2;
  CFRelease(protocol);if(services)CFRelease(services);CFRelease(prefs);
  return ok?0:1;
 }
}
