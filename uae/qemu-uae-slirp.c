/*
 * QEMU Slirp glue code for use with UAE
 * Copyright 2014 Frode Solheim <frode@fs-uae.net>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.	 See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/sockets.h"
#include "slirp/libslirp.h"
#include "qemu-uae.h"

#include "uae/log.h"
#include "uae/qemu.h"

UAE_DEFINE_IMPORT_FUNCTION(uae_slirp_output)

static Slirp *slirp;

#if 1
void qemu_uae_slirp_init(void)
#else
Slirp *qemu_uae_slirp_init(void *opaque)
#endif
{
    uae_log("QEMU: Initializing Slirp\n");

    int restricted = 0;
    const char *vhostname = NULL;
    const char *tftp_export = "";
    const char *bootfile = "";
    const char **dnssearch = NULL;

    struct in_addr net  = { .s_addr = htonl(0x0a000200) }; /* 10.0.2.0 */
    struct in_addr mask = { .s_addr = htonl(0xffffff00) }; /* 255.255.255.0 */
    struct in_addr host = { .s_addr = htonl(0x0a000202) }; /* 10.0.2.2 */
    struct in_addr dhcp = { .s_addr = htonl(0x0a00020f) }; /* 10.0.2.15 */
    struct in_addr dns  = { .s_addr = htonl(0x0a000203) }; /* 10.0.2.3 */

    //Slirp *
    slirp = slirp_init(restricted, net, mask, host, vhostname,
                       tftp_export, bootfile, dhcp, dns, dnssearch, NULL);
    //return slirp;
}

void qemu_uae_slirp_input(const uint8_t *pkt, int pkt_len)
{
    uae_log("QEMU: qemu_uae_slirp_input pkt_len %d\n", pkt_len);
    if (slirp == NULL) {
        return;
    }
    slirp_input(slirp, pkt, pkt_len);
}

void slirp_output(void *opaque, const uint8_t *pkt, int pkt_len)
{
    uae_log("QEMU: slirp_output pkt_len %d\n", pkt_len);
    if (uae_slirp_output == NULL) {
        return;
    }
    uae_slirp_output(pkt, pkt_len);
}
