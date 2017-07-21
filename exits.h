/*
 * exits.h -- Exit status
 *
 * Copyright (C) 2004 Henrique M. Holschuh <hmh@debian.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA  02110-1335  USA
 */

#ifndef EXITS__H
#define EXITS__H

/* Exit status */
#define EXIT_FAIL	1		/* Exit due to error */
#define EXIT_USAGE	10		/* Exit due to user error */
#define EXIT_IOERR	11		/* Exit due to I/O error */
#define EXIT_OSERR	12		/* Exit due to operating system error,
					   resource starvation, or another
					   non-app error */
#endif /* EXITS__H */
