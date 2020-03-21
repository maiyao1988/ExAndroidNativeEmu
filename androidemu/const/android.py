

PR_UNALIGN_NOPRINT=1	#/* silently fix up unaligned user accesses */
PR_UNALIGN_SIGBUS=2	#/* generate SIGBUS on unaligned user access */
PR_GET_DUMPABLE   =3
PR_SET_DUMPABLE   =4
PR_GET_UNALIGN	  =5
PR_SET_UNALIGN	  =6

PR_GET_KEEPCAPS   =7
PR_SET_KEEPCAPS   =8
PR_GET_FPEMU  =9
PR_SET_FPEMU =10
PR_GET_FPEXC	=11
PR_SET_FPEXC	=12
PR_GET_TIMING   =13
PR_SET_TIMING   =14
PR_TIMING_STATISTICAL  =0       #/* Normal, traditional,
PR_TIMING_TIMESTAMP    =1       #/* Accurate timestamp based
PR_SET_NAME=15		#/* Set process name */
PR_GET_NAME=16		#/* Get process name */

PR_SET_VMA = 0x53564d41