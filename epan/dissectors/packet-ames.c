/* packet-ames.c
 * Routines for ames dissection
 * Copyright 2023, Pyry Kovanen <pyry.kovanen@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * (A short description of the protocol including links to specifications,
 *  detailed documentation, etc.)
 */


#include "config.h"
/* Define the name for the logging domain (try to avoid collisions with existing domains) */
#define WS_LOG_DOMAIN "ames"

/* Global header providing a minimum base set of required macros and APIs */
#include <wireshark.h>

#if 0
/* "System" includes used only as needed */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
...
#endif

#include <epan/packet.h>   /* Required dissection API header */
#include <epan/expert.h>   /* Include only as needed */
#include <epan/prefs.h>    /* Include only as needed */

#if 0
/* IF AND ONLY IF your protocol dissector exposes code to other dissectors
 * (which most dissectors don't need to do) then the 'public' prototypes and
 * data structures can go in the header file packet-ames.h. If not, then
 * a header file is not needed at all and this #include statement can be
 * removed. */
#include "packet-ames.h"
#endif

/* Some protocols may need code from other dissectors, as here for
 * ssl_dissector_add()
 */
#include "packet-tls.h"

/* Prototypes */
/* (Required to prevent [-Wmissing-prototypes] warnings */
void proto_reg_handoff_ames(void);
void proto_register_ames(void);

/* Initialize the protocol and registered fields */
static int proto_ames;
static int reserved;
static int is_ames;
static int is_req;
static int version;
static int sender_size;
static int receiver_size;
static int checksum;
static int is_relayed;

static int sender_life;
static int clear_sender_life;
static int receiver_life;
static int clear_receiver_life;

static int sender_galaxy;
static int sender_star;
static int sender_planet;
static int receiver_galaxy;
static int receiver_star;
static int receiver_planet;

static int origin;
static int origin_null;

static int siv;
static int ciphertext_size;
static int ciphertext;

static expert_field ei_ames_expert;

static dissector_handle_t ames_handle;

/* Global sample preference ("controls" display of numbers) */
static gboolean pref_hex = false;

#define ames_UDP_PORTS "31337"
/* static unsigned udp_port_pref = 31337; */

/* Initialize the subtree pointers */
static int ett_ames;

/* A sample #define of the minimum length (in bytes) of the protocol data.
 * If data is received with fewer than this many bytes it is rejected by
 * the current dissector. */
#define ames_MIN_LENGTH 8

/* Code to actually dissect the packets */
static int
dissect_ames(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *ames_tree;
    /* Other misc. local variables. */
    unsigned offset = 0;
    int      len    = 4;

    /*** HEURISTICS ***/

    /* First, if at all possible, do some heuristics to check if the packet
     * cannot possibly belong to your protocol.  This is especially important
     * for protocols directly on top of TCP or UDP where port collisions are
     * common place (e.g., even though your protocol uses a well known port,
     * someone else may set up, for example, a web server on that port which,
     * if someone analyzed that web server's traffic in Wireshark, would result
     * in Wireshark handing an HTTP packet to your dissector).
     *
     * For example:
     */

    /* Check that the packet is long enough for it to belong to us. */
    if (tvb_reported_length(tvb) < ames_MIN_LENGTH)
        return 0;

    /* Check that there's enough data present to run the heuristics. If there
     * isn't, reject the packet; it will probably be dissected as data and if
     * the user wants it dissected despite it being short they can use the
     * "Decode-As" functionality. If your heuristic needs to look very deep into
     * the packet you may not want to require *all* data to be present, but you
     * should ensure that the heuristic does not access beyond the captured
     * length of the packet regardless. */
    if (tvb_captured_length(tvb) < 4)
        return 0;

    /* Fetch some values from the packet header using tvb_get_*(). If these
     * values are not valid/possible in your protocol then return 0 to give
     * some other dissector a chance to dissect it. */
    guint8 header = tvb_get_guint8(tvb, 0);
    if ((header & 0xc0) != 0) {
        g_print("we hit it\n");
        g_print("%x", header);
        return 0;
    }

    /*** COLUMN DATA ***/

    /* There are two normal columns to fill in: the 'Protocol' column which
     * is narrow and generally just contains the constant string 'ames',
     * and the 'Info' column which can be much wider and contain misc. summary
     * information (for example, the port number for TCP packets).
     *
     * If you are setting the column to a constant string, use "col_set_str()",
     * as it's more efficient than the other "col_set_XXX()" calls.
     *
     * If
     * - you may be appending to the column later OR
     * - you have constructed the string locally OR
     * - the string was returned from a call to val_to_str()
     * then use "col_add_str()" instead, as that takes a copy of the string.
     *
     * The function "col_add_fstr()" can be used instead of "col_add_str()"; it
     * takes "printf()"-like arguments. Don't use "col_add_fstr()" with a format
     * string of "%s" - just use "col_add_str()" or "col_set_str()", as it's
     * more efficient than "col_add_fstr()".
     *
     * For full details see section 1.4 of README.dissector.
     */

    /* Set the Protocol column to the constant string of ames */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ames");

#if 0
    /* If you will be fetching any data from the packet before filling in
     * the Info column, clear that column first in case the calls to fetch
     * data from the packet throw an exception so that the Info column doesn't
     * contain data left over from the previous dissector: */
    col_clear(pinfo->cinfo, COL_INFO);
#endif

    /*** PROTOCOL TREE ***/

    /* Now we will create a sub-tree for our protocol and start adding fields
     * to display under that sub-tree. Most of the time the only functions you
     * will need are proto_tree_add_item() and proto_item_add_subtree().
     *
     * NOTE: The offset and length values in the call to proto_tree_add_item()
     * define what data bytes to highlight in the hex display window when the
     * line in the protocol tree display corresponding to that item is selected.
     *
     * Supplying a length of -1 tells Wireshark to highlight all data from the
     * offset to the end of the packet.
     */

    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_ames, tvb, 0, -1, ENC_NA);

    ames_tree = proto_item_add_subtree(ti, ett_ames);

    /* Add an item to the subtree, see section 1.5 of README.dissector for more
     * information. */
    proto_tree_add_item(ames_tree, reserved, tvb,
            offset, len, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ames_tree, is_req, tvb,
            offset, len, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ames_tree, is_ames, tvb,
            offset, len, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ames_tree, version, tvb,
            offset, len, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(ames_tree, sender_size, tvb,
            offset, len, ENC_LITTLE_ENDIAN);

    /* guint32 sndr_size = tvb_get_guint32(tvb, 0, ENC_LITTLE_ENDIAN) & 0x00000180; */
    /* g_print("muna: %x\n", muna); */
    guint16 sndr_size = tvb_get_guint16(tvb, 0, ENC_LITTLE_ENDIAN);

    g_print("sndr_size: %x\n", sndr_size);

    proto_tree_add_item(ames_tree, receiver_size, tvb,
            offset, len, ENC_LITTLE_ENDIAN);

    /* guint32 rcvr_size = tvb_get_guint32(tvb, 0, ENC_LITTLE_ENDIAN) & 0x00000600; */
    guint8 rcvr_size = tvb_get_bits8(tvb, 13, 2);
    g_print("rcvr_size: %x\n", rcvr_size);


    proto_tree_add_item(ames_tree, checksum, tvb,
            offset, len, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ames_tree, is_relayed, tvb,
            offset, len, ENC_LITTLE_ENDIAN);
    guint32 relayed = tvb_get_guint32(tvb, 0, ENC_LITTLE_ENDIAN) >> 31;
    g_print("relayed: %u\n", relayed);
    offset += len;

    proto_tree_add_item(ames_tree, sender_life, tvb,
            offset, 1, ENC_LITTLE_ENDIAN);
    guint8 clr_sender_life = tvb_get_guint8(tvb, offset) % 16;
    ti = proto_tree_add_uint(ames_tree, clear_sender_life, tvb, offset, 1, clr_sender_life);
    proto_item_set_generated(ti);

    proto_tree_add_item(ames_tree, receiver_life, tvb,
            offset, 1, ENC_LITTLE_ENDIAN);
    guint8 clr_receiver_life = tvb_get_guint8(tvb, offset) % 16;
    ti = proto_tree_add_uint(ames_tree, clear_receiver_life, tvb, offset, 1, clr_receiver_life);
    proto_item_set_generated(ti);
    offset += 1;

    if (sndr_size == 0) {
        proto_tree_add_item(ames_tree, sender_galaxy, tvb,
            offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
    }
    else if (sndr_size == 2) {
        proto_tree_add_item(ames_tree, sender_star, tvb,
            offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
    }
    else if (sndr_size == 3) {
        proto_tree_add_item(ames_tree, sender_planet, tvb,
            offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
    }


    if (rcvr_size == 0) {
        proto_tree_add_item(ames_tree, receiver_galaxy, tvb,
            offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
    }
    else if (rcvr_size == 1) {
        proto_tree_add_item(ames_tree, receiver_planet, tvb,
            offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }
    else if (rcvr_size == 3) {
        proto_tree_add_item(ames_tree, receiver_planet, tvb,
            offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
    }

    if (relayed == 0) {
        proto_tree_add_item(ames_tree, origin, tvb,
            offset, 6, ENC_LITTLE_ENDIAN);
        offset += 6;

        proto_tree_add_item(ames_tree, siv, tvb,
            offset, 16, ENC_LITTLE_ENDIAN);
        offset += 16;
    } else {
        /* proto_tree_add_item(ames_tree, origin_null, tvb, */
        /*     offset, 1, ENC_LITTLE_ENDIAN); */
        proto_tree_add_bits_item(ames_tree, siv, tvb, (offset*8), 128, ENC_LITTLE_ENDIAN);

        offset += 16;
    }

    proto_tree_add_item(ames_tree, ciphertext_size, tvb,
        offset, 2, ENC_LITTLE_ENDIAN);
    guint16 cipher_size = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
    g_print("cipher_size: %u\n", cipher_size);
    offset += 2;

    /* proto_tree_add_bytes_format(ames_tree, ciphertext, tvb, */
    /*     offset, cipher_size, NULL, "Encrypted payload (%u bytes)", cipher_size); */
    /* Some fields or situations may require "expert" analysis that can be
     * specifically highlighted. */
    /* if ( 1 ) */
    /*     /\* value of ef_sample_field isn't what's expected *\/ */
    /*     expert_add_info(pinfo, expert_ti, &ei_ames_expert); */

    /* Continue adding tree items to process the packet here... */

    /* If this protocol has a sub-dissector call it here, see section 1.8 of
     * README.dissector for more information. */

    /* Return the amount of data this dissector was able to dissect (which may
     * or may not be the total captured packet as we return here). */
    return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark.
 *
 * This format is required because a script is used to build the C function that
 * calls all the protocol registration.
 */
void
proto_register_ames(void)
{
    module_t        *ames_module;
    expert_module_t *expert_ames;

    /* Setup list of header fields  See Section 1.5 of README.dissector for
     * details. */
    static hf_register_info hf[] = {
        { &reserved,
          { "reserved", "ames.reserved",
            FT_UINT32, BASE_HEX, NULL, 0x00000003,
            "NULL", HFILL }
        },
        { &is_req,
          { "is_req", "ames.is_req",
            FT_UINT32, BASE_HEX, NULL, 0x00000004,
            "NULL", HFILL }
        },
        { &is_ames,
          { "is_ames", "ames.is_ames",
            FT_UINT32, BASE_HEX, NULL, 0x00000008,
            "NULL", HFILL }
        },
        { &version,
          { "version", "ames.version",
            FT_UINT32, BASE_HEX, NULL, 0x00000070,
            "NULL", HFILL }
        },
        { &sender_size,
          { "sender_size", "ames.sender_size",
            FT_UINT32, BASE_HEX, NULL, 0x00000180,
            "NULL", HFILL }
        },
        { &receiver_size,
          { "receiver_size", "ames.sender_size",
            FT_UINT32, BASE_HEX, NULL, 0x00000600,
            "NULL", HFILL }
        },
        { &checksum,
          { "checksum", "ames.checksum",
            FT_UINT32, BASE_HEX, NULL, 0x7ffff800,
            "NULL", HFILL }
        },
        { &is_relayed,
          { "is_relayed", "ames.is_relayed",
            FT_UINT32, BASE_HEX, NULL, 0x80000000,
            "NULL", HFILL }
        },
        { &sender_life,
          { "Sender life", "ames.sender_life",
            FT_UINT8, BASE_HEX, NULL, 0xf0,
            "NULL", HFILL }
        },
        { &clear_sender_life,
          { "Sender life mod 16", "ames.clear_sender_life",
            FT_UINT8, BASE_DEC, NULL, 0xf0,
            "NULL", HFILL }
        },
        { &receiver_life,
          { "Receiver life", "ames.receiver_life",
            FT_UINT8, BASE_HEX, NULL, 0x0f,
            "NULL", HFILL }
        },
        { &clear_receiver_life,
          { "Receiver life mod 16", "ames.clear_receiver_life",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
            "NULL", HFILL }
        },
        { &sender_galaxy,
          { "Sender", "ames.sender",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "NULL", HFILL }
        },

        { &sender_star,
          { "Sender", "ames.sender",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "NULL", HFILL }
        },

        { &sender_planet,
          { "Sender", "ames.sender",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            "NULL", HFILL }
        },

        { &receiver_galaxy,
          { "Receiver", "ames.receiver",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "NULL", HFILL }
        },

        { &receiver_star,
          { "Receiver", "ames.receiver",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "NULL", HFILL }
        },

        { &receiver_planet,
          { "Receiver", "ames.receiver",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            "NULL", HFILL }
        },

        { &origin,
          { "Origin", "ames.origin",
            FT_UINT48, BASE_HEX, NULL, 0x0,
            "NULL", HFILL }
        },

        { &origin_null,
          { "Origin", "ames.origin",
            FT_UINT8, BASE_HEX, NULL, 0xc0,
            "NULL", HFILL }
        },

        { &siv,
          { "128 bit AES SIV", "ames.siv",
            FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0,
            "NULL", HFILL }
        },

        { &ciphertext_size,
          { "Encrypted payload size", "ames.ciphertext_size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "NULL", HFILL }
        },

        { &ciphertext,
          { "ciphertext", "ames.ciphertext",
            FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0,
            "NULL", HFILL }
        },
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_ames
    };

    /* Setup protocol expert items */
    static ei_register_info ei[] = {
        { &ei_ames_expert,
          { "ames.expert", PI_PROTOCOL, PI_ERROR,
            "EXPERTDESCR", EXPFILL }
        }
    };

    /* Register the protocol name and description */
    proto_ames = proto_register_protocol("ames", "ames", "PROTOFILTERNAME");

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_ames, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Required function calls to register expert items */
    expert_ames = expert_register_protocol(proto_ames);
    expert_register_field_array(expert_ames, ei, array_length(ei));

    /* Use register_dissector() here so that the dissector can be
     * found by name by other protocols, by Lua, by Export PDU,
     * by custom User DLT dissection, etc. Some protocols may require
     * multiple uniquely named dissectors that behave differently
     * depending on the caller, e.g. over TCP directly vs over TLS.
     */
    ames_handle = register_dissector("ames", dissect_ames,
            proto_ames);

    /* Register a preferences module (see section 2.6 of README.dissector
     * for more details). Registration of a prefs callback is not required
     * if there are no preferences that affect protocol registration (an example
     * of a preference that would affect registration is a port preference).
     * If the prefs callback is not needed, use NULL instead of
     * proto_reg_handoff_ames in the following.
     */
    ames_module = prefs_register_protocol(proto_ames,
            proto_reg_handoff_ames);

    /* Register a preferences module under the preferences subtree.
     * Only use this function instead of prefs_register_protocol (above) if you
     * want to group preferences of several protocols under one preferences
     * subtree.
     *
     * Argument subtree identifies grouping tree node name, several subnodes can
     * be specified using slash '/' (e.g. "OSI/X.500" - protocol preferences
     * will be accessible under Protocols->OSI->X.500-><ames>
     * preferences node.
     */
    ames_module = prefs_register_protocol_subtree("",
            proto_ames, proto_reg_handoff_ames);

    /* Register a simple example preference */
    prefs_register_bool_preference(ames_module, "show_hex",
            "Display numbers in Hex",
            "Enable to display numerical values in hexadecimal.",
            &pref_hex);

    /* Register an example port preference */
    /* prefs_register_uint_preference(ames_module, "udp.port", "ames UDP Port", */
    /*         " ames UDP port if other than the default", */
    /*         10, &udp_port_pref); */

}

/* If this dissector uses sub-dissector registration add a registration routine.
 * This exact format is required because a script is used to find these
 * routines and create the code that calls these routines.
 *
 * If this function is registered as a prefs callback (see
 * prefs_register_protocol above) this function is also called by Wireshark's
 * preferences manager whenever "Apply" or "OK" are pressed. In that case, it
 * should accommodate being called more than once by use of the static
 * 'initialized' variable included below.
 *
 * This form of the reg_handoff function is used if you perform registration
 * functions which are dependent upon prefs. See below this function for a
 * simpler form which can be used if there are no prefs-dependent registration
 * functions.
 */
void
proto_reg_handoff_ames(void)
{
    static bool initialized = false;

    if (!initialized) {
        /* Simple port preferences like TCP can be registered as automatic
         * Decode As preferences.
         */
        dissector_add_uint("udp.port", 31337, ames_handle);

        initialized = true;
    } else {
        /* If you perform registration functions which are dependent upon
         * prefs then you should de-register everything which was associated
         * with the previous settings and re-register using the new prefs
         * settings here. In general this means you need to keep track of
         * the value the preference had at the time you registered, which
         * can be saved using local statics in this function (proto_reg_handoff).
         */
        /* ssl_dissector_delete(current_tls_port_pref, ames_tls_handle); */
    }

    /* Some port preferences, like TLS, are more complicated and cannot
     * be done with auto preferences, because the TCP dissector has to call
     * TLS for the particular port as well as TLS calling this dissector.
     */
    /* ssl_dissector_add(tls_port_pref, ames_tls_handle); */
    /* current_tls_port = tls_port_pref; */
    /* Some protocols dissect packets going to the server port differently
     * than packets coming from the server port. The current Decode As
     * value can be retrieved here. Note that auto preferences are always
     * a range, even if registered with dissector_add_uint_with_preference.
     */
    /* tcp_port_range = prefs_get_range_value("ames", "tcp.port"); */
}

#if 0

/* Simpler form of proto_reg_handoff_ames which can be used if there are
 * no prefs-dependent registration function calls. */
void
proto_reg_handoff_ames(void)
{
    dissector_add_uint_range_with_preference("tcp.port", ames_TCP_PORTS, ames_handle);
}
#endif

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
