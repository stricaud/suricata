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

#include "util-privs.h"
#include "util-optimize.h"

#include "stream.h"

#include "alert-response.h"


typedef struct AlertResponseThread_ {
    SCMutex response_mutex;
} AlertResponseThread;


/**
 * \brief Loads and Initialize Response Modules
 *
 * \return the number of loaded response modules
 */
static int ResponseLoadModules(void)
{
  
    SCLogNotice("In %s\n", __FUNCTION__);
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

    SCEnter();

    ResponseLoadModules();

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

    /* if (unlikely(apn == NULL || apn->ctx == NULL)) { */
    /*     SCReturnInt(TM_ECODE_FAILED); */
    /* } */

    if (p->alerts.cnt == 0)
        SCReturnInt(TM_ECODE_OK);

    if ( !IPH_IS_VALID(p) )
        SCReturnInt(TM_ECODE_OK);

    for (i = 0; i < p->alerts.cnt; i++) {
        const PacketAlert *pa = &p->alerts.alerts[i];
        if (unlikely(pa->s == NULL)) {
            continue;
        }

	/* const char *action=""; */
	if (pa->action & ACTION_RESPONSE) {
	  SCLogNotice("This is a call for response");
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
