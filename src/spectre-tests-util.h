//==============================================================================
// This file is part of Spectre.
// Copyright (c) 2011-2017, Maarten Billemont.
//
// Spectre is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Spectre is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You can find a copy of the GNU General Public License in the
// LICENSE file.  Alternatively, see <http://www.gnu.org/licenses/>.
//==============================================================================

//
//  spectre-tests-util.h
//  Spectre
//
//  Created by Maarten Billemont on 2014-12-21.
//  Copyright (c) 2014 Lyndir. All rights reserved.
//

#include <libxml/parser.h>

xmlNodePtr spectre_xmlTestCaseNode(
        xmlNodePtr testCaseNode, const char *nodeName);
xmlChar *spectre_xmlTestCaseString(
        xmlNodePtr context, const char *nodeName);
uint32_t spectre_xmlTestCaseInteger(
        xmlNodePtr context, const char *nodeName);
