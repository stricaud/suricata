/* Copyright (C) 2007-2017 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Sebastien Tricaud <sebastien@honeynet.org>
 *
 * Respond to alerts.
 *
 */

#include <dirent.h>
#include <string.h>

#include <libnet.h>

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "flow.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-unittest.h"
#include "util-time.h"
#include "util-debug.h"
#include "util-error.h"
#include "util-print.h"

#include "output.h"

#include "util-device.h"
#include "util-privs.h"
#include "util-optimize.h"

#include "stream.h"

#include "alert-response.h"

#ifndef HAVE_LIBNET_INIT_CONST
#define LIBNET_INIT_CAST (char *)
#else
#define LIBNET_INIT_CAST
#endif

typedef struct AlertResponseThread_ {
    SCMutex response_mutex;
} AlertResponseThread;

typedef struct Libnet11ResponsePacket_ {
    uint32_t ack, seq;
    uint16_t window, dsize;
    uint8_t ttl;
    uint16_t id;
    uint32_t flow;
    uint8_t class;
    struct libnet_in6_addr src6, dst6;
    uint32_t src4, dst4;
    uint16_t sp, dp;
    size_t len;
} Libnet11ResponsePacket;

extern uint8_t host_mode;


/**
 * \brief Loads and Initialize Response Modules
 *
 * \return the number of loaded response modules. -1 on error;
 */
static int ResponseLoadModules(void)
{
    DIR *plugins_dir;
    struct dirent *item;

#ifndef HAVE_LIBNET11
    SCLogError("Libnet 11 is not installed or Suricata was not compiled with its support. Unable to respond.");
    return -1;
#endif

    SCLogNotice("In %s Loading plugins from %s\n", __FUNCTION__, RESPONSE_PLUGINS);
    
    plugins_dir = opendir(RESPONSE_PLUGINS);
    if (!plugins_dir) {
      SCLogError(SC_ERR_INITIALIZATION, "Error reading response plugins directory (%s): %s\n", RESPONSE_PLUGINS, strerror(errno));
      return -1;
    }
    while ((item = readdir(plugins_dir)) != NULL) {
      if (strncmp(item->d_name,".",1)) {
	SCLogNotice("Adding module:%s\n", item->d_name);
      }
    }
    closedir(plugins_dir);
    return 0;
}


static TmEcode AlertResponseThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    int ret;
    AlertResponseThread *art;

    SCEnter();

    if (unlikely(initdata == NULL)) {
        SCLogError(SC_ERR_INITIALIZATION,
                   "Error getting context for AlertResponseThreadInit.  \"initdata\" argument NULL");
        SCReturnInt(TM_ECODE_FAILED);
    }

    art = SCMalloc(sizeof(AlertResponseThread));
    if (unlikely(art == NULL))
        SCReturnInt(TM_ECODE_FAILED);
    memset(art, 0, sizeof(AlertResponseThread));

    /* Use the Output Context */
    /* art->ctx = ((OutputCtx *)initdata)->data; */

    *data = (void *)art;
    SCReturnInt(TM_ECODE_OK);
}

static TmEcode AlertResponseThreadDeinit(ThreadVars *t, void *data)
{
    AlertResponseThread *art = (AlertResponseThread *)data;

    SCEnter();

    if (unlikely(art == NULL)) {
        SCLogDebug("AlertResponseThreadDeinit done (error)");
        SCReturnInt(TM_ECODE_FAILED);
    }

    /* clear memory */
    memset(art, 0, sizeof(AlertResponseThread));
    SCFree(art);

    SCReturnInt(TM_ECODE_OK);
}

static void AlertResponseThreadDeinitCtx(OutputCtx *output_ctx)
{
    SCFree(output_ctx);
}

static OutputInitResult AlertResponseInit(ConfNode *conf)
{
    OutputInitResult result = { NULL, false };
    OutputCtx *output_ctx;
    int retval;
    
    SCEnter();

    retval = ResponseLoadModules();
    if (retval < 0) {
        SCReturnCT(result, "OutputInitResult");      
    }

    output_ctx = SCMalloc(sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        /* SCFree(ctx); */
        SCReturnCT(result, "OutputInitResult");
    }

    /* output_ctx->data = ctx; */
    output_ctx->DeInit = AlertResponseThreadDeinitCtx;

    result.ctx = output_ctx;
    result.ok = true;
    SCReturnCT(result, "OutputInitResult");
}

static int AlertResponseCondition(ThreadVars *tv, const Packet *p)
{
    if (p->alerts.cnt == 0)
        return FALSE;
    if (!IPH_IS_VALID(p))
        return FALSE;
    return TRUE;
}


int ResponseLibnet11IPv4TCP(ThreadVars *tv, Packet *p, const PacketAlert *pa, void *data)
{
    Libnet11ResponsePacket lpacket;
    libnet_t *ctx;
    char ebuf[LIBNET_ERRBUF_SIZE];
    int retval;
    const char *devname = NULL;

    //char *payload = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>foobar</html>\r\n\r\n";
    char *payload = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
    u_short payload_size = strlen(payload);

    p->flow->has_seen_response = 1;
    PACKET_DROP(p);
    printf("TCP GET DST PORT:%d\n",TCP_GET_DST_PORT(p));
    /* return 0; */
    
    SCLogNotice("We send the response!\n");
    
    /* fill in struct defaults */
    lpacket.ttl = 0;
    lpacket.id = 0;
    lpacket.flow = 0;
    lpacket.class = 0;

    if (IS_SURI_HOST_MODE_SNIFFER_ONLY(host_mode) && (p->livedev)) {
        devname = p->livedev->dev;
        SCLogDebug("Will emit reject packet on dev %s", devname);
    }
    if ((ctx = libnet_init(LIBNET_RAW4, LIBNET_INIT_CAST devname, ebuf)) == NULL) {
        SCLogError(SC_ERR_LIBNET_INIT,"libnet_init failed: %s", ebuf);
        return 1;
    }

    if (p->tcph == NULL)
       return 1;

    /* save payload len */
    /* lpacket.dsize = p->payload_len; */
    lpacket.dsize = 0;
    lpacket.window = TCP_GET_WINDOW(p);
    /* We follow http://tools.ietf.org/html/rfc793#section-3.4 :
     *  If packet has no ACK, the seq number is 0 and the ACK is built
     *  the normal way. If packet has a ACK, the seq of the RST packet
     *  is equal to the ACK of incoming packet and the ACK is build
     *  using packet sequence number and size of the data. */
    if (TCP_GET_ACK(p) == 0) {
        lpacket.seq = 0;
        lpacket.ack = TCP_GET_SEQ(p) + lpacket.dsize + 1;
    } else {
        lpacket.seq = TCP_GET_ACK(p);
        lpacket.ack = TCP_GET_SEQ(p) + lpacket.dsize;
    }
    
    lpacket.sp = TCP_GET_DST_PORT(p);
    lpacket.dp = TCP_GET_SRC_PORT(p);
    
    lpacket.src4 = GET_IPV4_DST_ADDR_U32(p);
    lpacket.dst4 = GET_IPV4_SRC_ADDR_U32(p);

    /* TODO come up with ttl calc function */
    lpacket.ttl = 64;

    /* build the package */
    if ((libnet_build_tcp(
		    lpacket.sp,            /* source port */
                    lpacket.dp,            /* dst port */
                    lpacket.seq,           /* seq number */
                    lpacket.ack,           /* ack number */
                    TH_ACK,                /* flags */
                    lpacket.window,        /* window size */
                    0,                     /* checksum */
                    0,                     /* urgent flag */
                    LIBNET_TCP_H,          /* header length */
                    NULL,                  /* payload */
                    0,                     /* payload length */
                    ctx,                     /* libnet context */
                    0)) < 0)               /* libnet ptag */
    {
        SCLogError(SC_ERR_LIBNET_BUILD_FAILED,"libnet_build_tcp %s", libnet_geterror(ctx));
        goto cleanup;
    }
    

    if ((libnet_build_ipv4(
                    LIBNET_TCP_H + LIBNET_IPV4_H, /* entire packet length */
                    0,                            /* tos */
                    lpacket.id,                   /* ID */
                    0,                            /* fragmentation flags and offset */
                    lpacket.ttl,                  /* TTL */
                    IPPROTO_TCP,                  /* protocol */
                    0,                            /* checksum */
                    lpacket.src4,                 /* source address */
                    lpacket.dst4,                 /* destination address */
                    NULL,                         /* pointer to packet data (or NULL) */
                    0,                            /* payload length */
                    ctx,                            /* libnet context pointer */
                    0)) < 0)                      /* packet id */
    {
        SCLogError(SC_ERR_LIBNET_BUILD_FAILED,"libnet_build_ipv4 %s", libnet_geterror(ctx));
        goto cleanup;
    }

    SCLogNotice("About to write the packet");
    /* libnet_diag_dump_context(ctx); */
    
    retval = libnet_write(ctx);
    if (retval == -1) {
        SCLogError(SC_ERR_LIBNET_WRITE_FAILED,"libnet_write failed: %s", libnet_geterror(ctx));
        goto cleanup;
    }

    /* Packet number 2 */
    if ((libnet_build_tcp(
		    lpacket.sp,            /* source port */
                    lpacket.dp,            /* dst port */
                    lpacket.seq,           /* seq number */
                    lpacket.ack,           /* ack number */
                    TH_PUSH|TH_ACK,                /* flags */
                    lpacket.window,        /* window size */
                    0,                     /* checksum */
                    0,                     /* urgent flag */
                    LIBNET_TCP_H + 20 + payload_size,          /* header length */
		    /* NULL, */
		    /* 0, */
                    (uint8_t *)payload,                  /* payload */
                    payload_size,                     /* payload length */
                    ctx,                     /* libnet context */
                    0)) < 0)               /* libnet ptag */
    {
        SCLogError(SC_ERR_LIBNET_BUILD_FAILED,"libnet_build_tcp %s", libnet_geterror(ctx));
        goto cleanup;
    }
    
    if ((libnet_build_ipv4(
                    LIBNET_TCP_H + LIBNET_IPV4_H, /* entire packet length */
                    0,                            /* tos */
                    lpacket.id,                   /* ID */
                    0,                            /* fragmentation flags and offset */
                    lpacket.ttl,                  /* TTL */
                    IPPROTO_TCP,                  /* protocol */
                    0,                            /* checksum */
                    lpacket.src4,                 /* source address */
                    lpacket.dst4,                 /* destination address */
                    NULL,                         /* pointer to packet data (or NULL) */
                    0,                            /* payload length */
                    ctx,                            /* libnet context pointer */
                    0)) < 0)                      /* packet id */
    {
        SCLogError(SC_ERR_LIBNET_BUILD_FAILED,"libnet_build_ipv4 %s", libnet_geterror(ctx));
        goto cleanup;
    }

    SCLogNotice("About to write the packet");
    /* libnet_diag_dump_context(ctx); */
    
    retval = libnet_write(ctx);
    if (retval == -1) {
        SCLogError(SC_ERR_LIBNET_WRITE_FAILED,"libnet_write failed: %s", libnet_geterror(ctx));
        goto cleanup;
    }    
    
cleanup:
    libnet_destroy (ctx);
    return 0;    
}

/**
 * \brief Handle Suricata alert: push out alert into our response module.
 *
 * \return TM_ECODE_OK if ok, else TM_ECODE_FAILED
 */
static int AlertResponseAction(ThreadVars *tv, void *thread_data, const Packet *p)
{
    AlertResponseThread *apn = (AlertResponseThread *)thread_data;
    int ret;
    int i;
    const PacketAlert *pa;

    
    SCEnter();

#ifndef HAVE_LIBNET11    
    SCReturnInt(TM_ECODE_FAILED);
#endif
    
    /* if (unlikely(apn == NULL || apn->ctx == NULL)) { */
    /*     SCReturnInt(TM_ECODE_FAILED); */
    /* } */
    if (unlikely(apn == NULL)) {
        SCReturnInt(TM_ECODE_FAILED);
    }

    if (p->alerts.cnt == 0)
        SCReturnInt(TM_ECODE_OK);

    if ( !IPH_IS_VALID(p) )
        SCReturnInt(TM_ECODE_OK);

    for (i = 0; i < p->alerts.cnt; i++) {
        const PacketAlert *pa = &p->alerts.alerts[i];
        if (unlikely(pa->s == NULL)) {
            continue;
        }

	if (pa->action & ACTION_RESPONSE) {
	  SCLogNotice("This is a call for response for %s\n", pa->s->msg);
	  ResponseLibnet11IPv4TCP(tv, p, pa, NULL);
	  
	}
    }
    

    SCReturnInt(TM_ECODE_OK);

err:
    SCReturnInt(TM_ECODE_FAILED);
}

void AlertResponseRegister (void)
{
    OutputRegisterPacketModule(LOGGER_RESPONSE, "AlertResponse", "alert-response",
        AlertResponseInit, AlertResponseAction, AlertResponseCondition,
        AlertResponseThreadInit, AlertResponseThreadDeinit, NULL);
}
