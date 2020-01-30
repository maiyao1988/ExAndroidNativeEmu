CLOCK_REALTIME = 0
CLOCK_MONOTONIC = 1
CLOCK_PROCESS_CPUTIME_ID = 2
CLOCK_THREAD_CPUTIME_ID = 3
CLOCK_MONOTONIC_RAW = 4
CLOCK_REALTIME_COARSE = 5
CLOCK_MONOTONIC_COARSE = 6
CLOCK_BOOTTIME = 7
CLOCK_REALTIME_ALARM = 8
CLOCK_BOOTTIME_ALARM = 9

FUTEX_WAIT = 0
FUTEX_WAKE = 1
FUTEX_FD = 2
FUTEX_REQUEUE = 3
FUTEX_CMP_REQUEUE = 4
FUTEX_WAKE_OP = 5
FUTEX_LOCK_PI = 6
FUTEX_UNLOCK_PI = 7
FUTEX_TRYLOCK_PI = 8
FUTEX_WAIT_BITSET = 9
FUTEX_WAKE_BITSET = 10
FUTEX_WAIT_REQUEUE_PI = 11
FUTEX_CMP_REQUEUE_PI = 12

FUTEX_PRIVATE_FLAG = 128
FUTEX_CLOCK_REALTIME = 256

FUTEX_CMD_MASK = ~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME)

#fcntl
#/* command values */
F_DUPFD=0		#/* duplicate file descriptor */
F_GETFD=1		#/* get file descriptor flags */
F_SETFD=2		#/* set file descriptor flags */
F_GETFL=3		#/* get file status flags */
F_SETFL=4		#/* set file status flags */
F_GETOWN=5	#/* get SIGIO/SIGURG proc/pgrp */
F_SETOWN=6	#/* set SIGIO/SIGURG proc/pgrp */
F_GETLK=7		#/* get record locking information */
F_SETLK=8		#/* set record locking information */
F_SETLKW=9	#/* F_SETLK; wait if blocked */

#/* file descriptor flags (F_GETFD, F_SETFD) */
FD_CLOEXEC=1		#/* close-on-exec flag */

#/* record locking flags (F_GETLK, F_SETLK, F_SETLKW) */
F_RDLCK=1		#/* shared or read lock */
F_UNLCK=2		#/* unlock */
F_WRLCK=3		#/* exclusive or write lock */
F_WAIT=0x010		#/* Wait until lock is granted */
F_FLOCK=0x020	 	#/* Use flock(2) semantics for lock */
F_POSIX=0x040	 	#/* Use POSIX semantics for lock */
