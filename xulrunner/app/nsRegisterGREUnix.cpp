/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is Mozilla XULRunner.
 *
 * The Initial Developer of the Original Code is
 * Benjamin Smedberg <benjamin@smedbergs.us>.
 *
 * Portions created by the Initial Developer are Copyright (C) 2005
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */

#include "nsRegisterGRE.h"

#include "nsIFile.h"
#include "nsILocalFile.h"

#include "nsBuildID.h"
#include "nsAppRunner.h" // for MAXPATHLEN
#include "nsString.h"
#include "nsINIParser.h"

#include "prio.h"
#include "prprf.h"
#include "prenv.h"

#include <unistd.h>
#include <sys/stat.h>

// If we can't register <buildid>.conf, we try to create a unique filename
// by looping through <buildid>_<int>.conf, but if something is seriously wrong
// we stop at 1000
#define UNIQ_LOOP_LIMIT 1000

static const char kRegFileGlobal[] = "global.reginfo";
static const char kRegFileUser[] = "user.reginfo";
static const char kGREBuildID[] = GRE_BUILD_ID;

class AutoFDClose
{
public:
  AutoFDClose(PRFileDesc* fd = nsnull) : mFD(fd) { }
  ~AutoFDClose() { if (mFD) PR_Close(mFD); }

  PRFileDesc* operator= (PRFileDesc *fd) {
    if (mFD) PR_Close(mFD);
    mFD = fd;
    return fd;
  }

  operator PRFileDesc* () { return mFD; }
  PRFileDesc** operator &() { *this = nsnull; return &mFD; }

private:
  PRFileDesc *mFD;
};

static PRBool
MakeConfFile(const char *regfile, const nsCString &greHome)
{
  // If the file exists, don't create it again!
  if (access(regfile, R_OK) == 0)
    return PR_FALSE;

  PRBool ok = PR_TRUE;

  { // scope "fd" so that we can delete the file if something goes wrong
    AutoFDClose fd = PR_Open(regfile, PR_CREATE_FILE | PR_WRONLY | PR_TRUNCATE,
                             0664);
    if (!fd)
      return PR_FALSE;

    static const char kHeader[] =
      "# Registration file generated by xulrunner. Do not edit.\n\n"
      "[" GRE_BUILD_ID "]\n"
      "GRE_PATH=";

    if (PR_Write(fd, kHeader, sizeof(kHeader) - 1) != sizeof(kHeader) - 1)
      ok = PR_FALSE;

    if (PR_Write(fd, greHome.get(), greHome.Length()) != greHome.Length())
      ok = PR_FALSE;

    PR_Write(fd, "\n", 1);
  }

  if (!ok)
    PR_Delete(regfile);

  return ok;
}


PRBool
RegisterXULRunner(PRBool aRegisterGlobally, nsIFile* aLocation)
{
  // Register ourself in /etc/gre.d or ~/.gre.d/ and record what key we created
  // for future unregistration.

  nsresult rv;

  char root[MAXPATHLEN] = "/etc/gre.d";

  if (!aRegisterGlobally) {
    char *home = PR_GetEnv("HOME");
    if (!home || !*home)
      return PR_FALSE;

    PR_snprintf(root, MAXPATHLEN, "%s/.gre.d", home);
  }

  nsCAutoString greHome;
  rv = aLocation->GetNativePath(greHome);
  if (NS_FAILED(rv))
    return rv;

  nsCOMPtr<nsIFile> savedInfoFile;
  aLocation->Clone(getter_AddRefs(savedInfoFile));
  nsCOMPtr<nsILocalFile> localSaved(do_QueryInterface(savedInfoFile));
  if (!localSaved)
    return PR_FALSE;

  const char *infoname = aRegisterGlobally ? kRegFileGlobal : kRegFileUser;
  localSaved->AppendNative(nsDependentCString(infoname));

  AutoFDClose fd;
  rv = localSaved->OpenNSPRFileDesc(PR_CREATE_FILE | PR_RDWR, 0664, &fd);
  // XXX report error?
  if (NS_FAILED(rv))
    return PR_FALSE;

  char keyName[MAXPATHLEN];

  PRInt32 r = PR_Read(fd, keyName, MAXPATHLEN);
  if (r < 0)
    return PR_FALSE;

  char regfile[MAXPATHLEN];

  if (r > 0) {
    keyName[r] = '\0';

    PR_snprintf(regfile, MAXPATHLEN, "%s/%s.conf", root, keyName);

    // There was already a .reginfo file, let's see if we are already
    // registered.
    if (access(regfile, R_OK) == 0) {
      fprintf(stderr, "Warning: Configuration file '%s' already exists.\n"
                      "No action was performed.\n", regfile);
      return PR_FALSE;
    }

    rv = localSaved->OpenNSPRFileDesc(PR_CREATE_FILE | PR_WRONLY | PR_TRUNCATE, 0664, &fd);
    if (NS_FAILED(rv))
      return PR_FALSE;
  }

  if (access(root, R_OK | X_OK) &&
      mkdir(root, 0775)) {
    fprintf(stderr, "Error: could not create '%s'.\n",
            root);
    return PR_FALSE;
  }

  PR_snprintf(regfile, MAXPATHLEN, "%s/%s.conf", root, kGREBuildID);
  if (MakeConfFile(regfile, greHome)) {
    PR_Write(fd, kGREBuildID, sizeof(kGREBuildID) - 1);
    return PR_TRUE;
  }

  for (int i = 0; i < UNIQ_LOOP_LIMIT; ++i) {
    static char buildID[30];
    sprintf(buildID, "%s_%i", kGREBuildID, i);

    PR_snprintf(regfile, MAXPATHLEN, "%s/%s.conf", root, buildID);

    if (MakeConfFile(regfile, greHome)) {
      PR_Write(fd, buildID, strlen(buildID));
      return PR_TRUE;
    }
  }

  return PR_FALSE;
}

void
UnregisterXULRunner(PRBool aRegisterGlobally, nsIFile* aLocation)
{
  nsresult rv;

  char root[MAXPATHLEN] = "/etc/gre.d";

  if (!aRegisterGlobally) {
    char *home = PR_GetEnv("HOME");
    if (!home || !*home)
      return;

    PR_snprintf(root, MAXPATHLEN, "%s/.gre.d", home);
  }

  nsCOMPtr<nsIFile> savedInfoFile;
  aLocation->Clone(getter_AddRefs(savedInfoFile));
  nsCOMPtr<nsILocalFile> localSaved (do_QueryInterface(savedInfoFile));
  if (!localSaved)
    return;

  const char *infoname = aRegisterGlobally ? kRegFileGlobal : kRegFileUser;
  localSaved->AppendNative(nsDependentCString(infoname));

  PRFileDesc* fd = nsnull;
  rv = localSaved->OpenNSPRFileDesc(PR_RDONLY, 0, &fd);
  if (NS_FAILED(rv)) {
    // XXX report error?
    return;
  }

  char keyName[MAXPATHLEN];
  PRInt32 r = PR_Read(fd, keyName, MAXPATHLEN);
  PR_Close(fd);

  localSaved->Remove(PR_FALSE);

  if (r <= 0)
    return;

  keyName[r] = '\0';

  char regFile[MAXPATHLEN];
  PR_snprintf(regFile, MAXPATHLEN, "%s/%s.conf", root, keyName);

  nsCOMPtr<nsILocalFile> lf;
  rv = NS_NewNativeLocalFile(nsDependentCString(regFile), PR_FALSE,
                             getter_AddRefs(lf));
  if (NS_FAILED(rv))
    return;

  nsINIParser p;
  rv = p.Init(lf);
  if (NS_FAILED(rv))
    return;

  rv = p.GetString(kGREBuildID, "GRE_PATH", root, MAXPATHLEN);
  if (NS_FAILED(rv))
    return;

  rv = NS_NewNativeLocalFile(nsDependentCString(root), PR_TRUE,
                             getter_AddRefs(lf));
  if (NS_FAILED(rv))
    return;

  PRBool eq;
  if (NS_SUCCEEDED(aLocation->Equals(lf, &eq)) && eq)
    PR_Delete(regFile);
}
