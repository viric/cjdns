/* vim: set expandtab ts=4 sw=4: */
/*
 * You may redistribute this program and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "exception/Except.h"
#include "interface/Interface.h"
#include "interface/MultiInterface.h"
#include "interface/UDPInterface.h"
#include "interface/addressable/UDPAddrInterface.h"
#include "interface/UDPInterface_pvt.h"
#include "memory/Allocator.h"
#include "interface/InterfaceController.h"
#include "util/platform/Sockaddr.h"
#include "wire/Message.h"

#include <stdlib.h>

int UDPInterface_beginConnection(const char* address,
                                 uint8_t cryptoKey[32],
                                 String* password,
                                 struct UDPInterface* udp)
{
    struct UDPInterface_pvt* udpif = (struct UDPInterface_pvt*) udp;
    struct Sockaddr_storage ss;
    struct Sockaddr* addr;

    struct Allocator* tempAlloc = Allocator_child(udpif->alloc);

    if (!Sockaddr_parse(address, &ss)) {
        addr = &ss.addr;
    } else {
        // Attempt name resolution
        String *address2 = String_new(address, tempAlloc);
        char* lastColon = CString_strrchr(address2->bytes, ':');
        if (lastColon) {
            // try it as a hostname.
            int port = atoi(lastColon+1);
            if (!port) {
                Log_critical(udpif->logger, "Couldn't get port number from [%s]", address);
                exit(-1);
            }
            *lastColon = '\0';
            addr = Sockaddr_fromName(address2->bytes, tempAlloc);
            if (addr != NULL) {
                Sockaddr_setPort(addr, port);
            } else {
                Log_warn(udpif->logger, "Failed to lookup hostname [%s]", address2->bytes);
                Allocator_free(tempAlloc);
                return UDPInterface_beginConnection_BAD_ADDRESS;
            }
        } else {
            Allocator_free(tempAlloc);
            return UDPInterface_beginConnection_BAD_ADDRESS;
        }
    }

    if (Sockaddr_getFamily(addr) != Sockaddr_getFamily(udp->addr)) {
        return UDPInterface_beginConnection_ADDRESS_MISMATCH;
    }


    char* addrPtr = NULL;
    int addrLen = Sockaddr_getAddress(addr, &addrPtr);
    Assert_true(addrLen > 0);
    if (Bits_isZero(addrPtr, addrLen)) {
        // unspec'd address, convert to loopback
        if (Sockaddr_getFamily(addr) == Sockaddr_AF_INET) {
            addr = Sockaddr_clone(Sockaddr_LOOPBACK, tempAlloc);
        } else if (Sockaddr_getFamily(addr) == Sockaddr_AF_INET6) {
            addr = Sockaddr_clone(Sockaddr_LOOPBACK6, tempAlloc);
        } else {
            Assert_failure("Sockaddr which is not AF_INET nor AF_INET6");
        }
        Sockaddr_setPort(addr, Sockaddr_getPort(addr));
    }

    struct Interface* iface = MultiInterface_ifaceForKey(udpif->multiIface, addr);
    int ret = InterfaceController_registerPeer(udpif->ic, cryptoKey, password, false, false, iface);
    Allocator_free(tempAlloc);
    if (ret) {
        Allocator_free(iface->allocator);
        switch(ret) {
            case InterfaceController_registerPeer_BAD_KEY:
                return UDPInterface_beginConnection_BAD_KEY;

            case InterfaceController_registerPeer_OUT_OF_SPACE:
                return UDPInterface_beginConnection_OUT_OF_SPACE;

            default:
                return UDPInterface_beginConnection_UNKNOWN_ERROR;
        }
    }
    return 0;
}

struct UDPInterface* UDPInterface_new(struct EventBase* base,
                                      struct Sockaddr* bindAddr,
                                      struct Allocator* allocator,
                                      struct Except* exHandler,
                                      struct Log* logger,
                                      struct InterfaceController* ic)
{
    struct AddrInterface* udpBase =
        UDPAddrInterface_new(base, bindAddr, allocator, exHandler, logger);

    struct UDPInterface_pvt* context = Allocator_malloc(allocator, sizeof(struct UDPInterface_pvt));
    Bits_memcpyConst(context, (&(struct UDPInterface_pvt) {
        .pub = {
            .addr = udpBase->addr
        },
        .udpBase = udpBase,
        .logger = logger,
        .ic = ic,
        .alloc = allocator
    }), sizeof(struct UDPInterface_pvt));

    context->multiIface =
        MultiInterface_new(context->pub.addr->addrLen, &udpBase->generic, ic, logger);

    return &context->pub;
}
