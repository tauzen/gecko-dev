/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* ***** BEGIN LICENSE BLOCK *****
 * Version: NPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Netscape Public License
 * Version 1.1 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 * http://www.mozilla.org/NPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is mozilla.org code.
 *
 * The Initial Developer of the Original Code is 
 * Netscape Communications Corporation.
 * Portions created by the Initial Developer are Copyright (C) 2002
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
 * use your version of this file under the terms of the NPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the NPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */

#import "CHBrowserView.h"
#import "BookmarksService.h"
#include "nsIDocument.h"
#include "nsIContent.h"
#include "nsIAtom.h"
#include "nsITextContent.h"
#include "nsIDOMWindow.h"
#include "nsIDOMHTMLDocument.h"
#include "nsIDOMElement.h"
#include "nsIDOMCharacterData.h"
#include "nsIPrefBranch.h"
#include "nsString.h"
#include "nsCRT.h"
#include "nsIFile.h"
#include "nsAppDirectoryServiceDefs.h"
#include "nsIXMLHttpRequest.h"
#include "nsIDOMSerializer.h"
#include "nsNetUtil.h"
#include "nsINamespaceManager.h"
#include "nsIXBLService.h"
#include "nsIWebBrowser.h"

@implementation BookmarksDataSource

-(id) init
{
    if ( (self = [super init]) ) {
        mBookmarks = nsnull;
        mCachedHref = nil;
    }
    return self;
}

-(void) dealloc
{
  [super dealloc];
}

-(void) windowClosing
{
  if (mBookmarks) {
    mBookmarks->RemoveObserver();
    delete mBookmarks;
  }
}

-(void) ensureBookmarks
{
    if (mBookmarks)
        return;
    
    mBookmarks = new BookmarksService(self);
    mBookmarks->AddObserver();
    
    [mOutlineView setTarget: self];
    [mOutlineView setDoubleAction: @selector(openBookmark:)];
    [mOutlineView setDeleteAction: @selector(deleteBookmarks:)];
    [mOutlineView reloadData];
}

-(IBAction)addBookmark:(id)aSender
{
  [self addBookmark: aSender useSelection: YES isFolder: NO];
}

-(IBAction)addFolder:(id)aSender
{
  [self addBookmark: aSender useSelection: YES isFolder: YES];
}

-(void)addBookmark:(id)aSender useSelection:(BOOL)aUseSel isFolder:(BOOL)aIsFolder
{
  if (!mBookmarks)
    return;

  // We use the selected item to determine the parent only if aUseSel is YES.
  BookmarkItem* item = nil;
  if (aUseSel && ([mOutlineView numberOfSelectedRows] == 1)) {
    // There is only one selected row.  If it is a folder, use it as our parent.
    // Otherwise, use our parent,
    int index = [mOutlineView selectedRow];
    item = [mOutlineView itemAtRow: index];
    if (![mOutlineView isExpandable: item]) {
      // We can't be used as the parent.  Try our parent.
      nsIContent* content = [item contentNode];
      nsCOMPtr<nsIContent> parentContent;
      content->GetParent(*getter_AddRefs(parentContent));
      nsCOMPtr<nsIContent> root;
      mBookmarks->GetRootContent(getter_AddRefs(root));
      
      // The root has no item, so we don't need to do a lookup unless we
      // aren't the root.
      if (parentContent != root) {
        PRUint32 contentID;
        parentContent->GetContentID(&contentID);
        item = [(BookmarksService::gDictionary) objectForKey: [NSNumber numberWithInt: contentID]];
      }
    }
  }

  nsCOMPtr<nsIDOMDocument> domDoc(do_QueryInterface(mBookmarks->gBookmarks));
  
  // Fetch the title of the current page and the URL.
  nsAutoString title, href;
  if (!aIsFolder) {
    BookmarksService::GetTitleAndHrefForBrowserView([[mBrowserWindowController getBrowserWrapper] getBrowserView],
                                                    title, href);

    mCachedHref = [NSString stringWithCharacters: href.get() length: href.Length()];
    [mCachedHref retain];
  }
  else {
    mCachedHref = nil;
    title = NS_LITERAL_STRING("New Folder");
  }
  
  NSTextField* textField = [mBrowserWindowController getAddBookmarkTitle];
  [textField setStringValue: [NSString stringWithCharacters: title.get() length: title.Length()]];

  [mBrowserWindowController cacheBookmarkDS: self];

  // Show/hide the bookmark all tabs checkbox as appropriate.
  NSTabView* tabView = [mBrowserWindowController getTabBrowser];
  id checkbox = [mBrowserWindowController getAddBookmarkCheckbox];
  BOOL hasSuperview = [checkbox superview] != nil;
  if (aIsFolder && hasSuperview) {
    // Just don't show it at all.
    [checkbox removeFromSuperview];
    [checkbox retain];
  }
  else if (!aIsFolder && !hasSuperview) {
    // Put it back in.
    [[[mBrowserWindowController getAddBookmarkSheetWindow] contentView] addSubview: checkbox];
    [checkbox autorelease];
  }

  // Enable the bookmark all tabs checkbox if appropriate.
  if (!aIsFolder)
    [[mBrowserWindowController getAddBookmarkCheckbox] setEnabled: ([tabView numberOfTabViewItems] > 1)];
  
  // Build up the folder list.
  NSPopUpButton* popup = [mBrowserWindowController getAddBookmarkFolder];
  BookmarksService::ConstructAddBookmarkFolderList(popup, item);
  
  [NSApp beginSheet:	[mBrowserWindowController getAddBookmarkSheetWindow]
     modalForWindow:	[mBrowserWindowController window]
      modalDelegate:	nil //self
     didEndSelector:	nil //@selector(sheetDidEnd:)
        contextInfo:	nil];
}

-(void)endAddBookmark: (int)aCode
{
  if (aCode == 0)
    return;

  BOOL isGroup = NO;
  id checkbox = [mBrowserWindowController getAddBookmarkCheckbox];
  if (([checkbox superview] != nil) && [checkbox isEnabled] && ([checkbox state] == NSOnState)) {
    mCachedHref = nil;
    isGroup = YES;
  }
  
  const char* titleC = [[[mBrowserWindowController getAddBookmarkTitle] stringValue] cString];
  nsAutoString title; title.AssignWithConversion(titleC);

  nsAutoString tagName;
  if (mCachedHref)
    tagName = NS_LITERAL_STRING("bookmark");
  else
    tagName = NS_LITERAL_STRING("folder");
  
  nsCOMPtr<nsIDOMDocument> domDoc(do_QueryInterface(mBookmarks->gBookmarks));
  nsCOMPtr<nsIDOMElement> elt;
  domDoc->CreateElementNS(NS_LITERAL_STRING("http://chimera.mozdev.org/bookmarks/"),
                          tagName,
                          getter_AddRefs(elt));

  elt->SetAttribute(NS_LITERAL_STRING("name"), title);

  if (mCachedHref) {
    nsAutoString href; href.AssignWithConversion([mCachedHref cString]);
    [mCachedHref release];
    elt->SetAttribute(NS_LITERAL_STRING("href"), href);
  }

  if (isGroup) {
    // We have to iterate over each tab and create content nodes using the
    // title/href of all the pages.  They are inserted underneath the parent.
    elt->SetAttribute(NS_LITERAL_STRING("group"), NS_LITERAL_STRING("true"));
    id tabBrowser = [mBrowserWindowController getTabBrowser];
    int count = [tabBrowser numberOfTabViewItems];
    for (int i = 0; i < count; i++) {
      id browserView = [[[tabBrowser tabViewItemAtIndex: i] view] getBrowserView];
      nsAutoString title, href;
      BookmarksService::GetTitleAndHrefForBrowserView(browserView, title, href);
      nsCOMPtr<nsIDOMElement> childElt;
      domDoc->CreateElementNS(NS_LITERAL_STRING("http://chimera.mozdev.org/bookmarks/"),
                              NS_LITERAL_STRING("bookmark"),
                              getter_AddRefs(childElt));
      childElt->SetAttribute(NS_LITERAL_STRING("name"), title);
      childElt->SetAttribute(NS_LITERAL_STRING("href"), href);
      nsCOMPtr<nsIDOMNode> dummy;
      elt->AppendChild(childElt, getter_AddRefs(dummy));
    }
  }
  
  // Figure out the parent element.
  nsCOMPtr<nsIDOMElement> parentElt;
  nsCOMPtr<nsIContent> parentContent;
  NSPopUpButton* popup = [mBrowserWindowController getAddBookmarkFolder];
  NSMenuItem* selectedItem = [popup selectedItem];
  int tag = [selectedItem tag];
  if (tag == -1) {
    mBookmarks->GetRootContent(getter_AddRefs(parentContent));
    parentElt = do_QueryInterface(parentContent);
  }
  else {
    BookmarkItem* item = [(BookmarksService::gDictionary) objectForKey: [NSNumber numberWithInt: tag]];
    // Get the content node.
    parentContent = [item contentNode];
    parentElt = do_QueryInterface(parentContent);
  }
  
  nsCOMPtr<nsIDOMNode> dummy;
  parentElt->AppendChild(elt, getter_AddRefs(dummy));

  nsCOMPtr<nsIContent> childContent(do_QueryInterface(elt));
  mBookmarks->BookmarkAdded(parentContent, childContent);
}

-(IBAction)deleteBookmarks: (id)aSender
{
  if (!mBookmarks)
    return;

  int index = [mOutlineView selectedRow];
  if (index == -1)
    return;
  if ([mOutlineView numberOfSelectedRows] == 1) {
    BookmarkItem* item = [mOutlineView itemAtRow: index];
    [self deleteBookmark: item];
    int total = [mOutlineView numberOfRows];
    if (index == total)
      index--;
    [mOutlineView selectRow: index byExtendingSelection: NO];
  }
  else {
    NSMutableArray* itemsToDelete = [[[NSMutableArray alloc] init] autorelease];
    NSEnumerator* selRows = [mOutlineView selectedRowEnumerator];
    for (NSNumber* currIndex = [selRows nextObject];
         currIndex != nil;
         currIndex = [selRows nextObject]) {
      index = [currIndex intValue];
      BookmarkItem* item = [mOutlineView itemAtRow: index];
      [itemsToDelete addObject: item];
    }

    int count = [itemsToDelete count];
    for (int i = 0; i < count; i++) {
      BookmarkItem* item = [itemsToDelete objectAtIndex: i];
      [self deleteBookmark: item];	
    }
  }
}	

-(void)deleteBookmark:(id)aItem
{
  nsCOMPtr<nsIContent> content = [aItem contentNode];
  nsCOMPtr<nsIDOMElement> child(do_QueryInterface(content));
  if (child == BookmarksService::gToolbarRoot)
    return; // Don't allow the personal toolbar to be deleted.
  
  nsCOMPtr<nsIDOMNode> parent;
  child->GetParentNode(getter_AddRefs(parent));
  nsCOMPtr<nsIContent> parentContent(do_QueryInterface(parent));
  nsCOMPtr<nsIDOMNode> dummy;
  parent->RemoveChild(child, getter_AddRefs(dummy));
  mBookmarks->BookmarkRemoved(parentContent, content);
}

-(IBAction)openBookmark: (id)aSender
{
  int index = [mOutlineView selectedRow];
  if (index == -1)
    return;

  id item = [mOutlineView itemAtRow: index];
  if (!item)
    return;

  nsIContent* content = [item contentNode];
  nsCOMPtr<nsIDOMElement> elt(do_QueryInterface(content));
  nsAutoString group;
  elt->GetAttribute(NS_LITERAL_STRING("group"), group);
  if (!group.IsEmpty())
    mBookmarks->OpenBookmarkGroup([mBrowserWindowController getTabBrowser], elt);
  else if ([mOutlineView isExpandable: item]) {
    if ([mOutlineView isItemExpanded: item])
      [mOutlineView collapseItem: item];
    else
      [mOutlineView expandItem: item];
  }
  else {
    nsAutoString href;
    content->GetAttr(kNameSpaceID_None, BookmarksService::gHrefAtom, href);
    if (!href.IsEmpty()) {
      NSString* url = [NSString stringWithCharacters: href.get() length: href.Length()];
      [[[mBrowserWindowController getBrowserWrapper] getBrowserView] loadURI:[NSURL URLWithString: url] flags:			NSLoadFlagsNone];
      // Focus and activate our content area.
      [[[mBrowserWindowController getBrowserWrapper] getBrowserView] setActive: YES];
    }
  }
}


//
// outlineView:shouldEditTableColumn:item: (delegate method)
//
// Called by the outliner to determine whether or not we should allow the 
// user to edit this item. For now, Cocoa doesn't correctly handle editing
// of attributed strings with icons, so we can't turn this on. :(
//
- (BOOL)outlineView:(NSOutlineView *)outlineView shouldEditTableColumn:(NSTableColumn *)tableColumn item:(id)item
{
	return NO;
}

- (id)outlineView:(NSOutlineView *)outlineView child:(int)index ofItem:(id)item
{
    if (!mBookmarks)
        return nil;
       
    nsCOMPtr<nsIContent> content;
    if (!item)
        mBookmarks->GetRootContent(getter_AddRefs(content));
    else
        content = [item contentNode];
    
    nsCOMPtr<nsIContent> child;
    content->ChildAt(index, *getter_AddRefs(child));
    return mBookmarks->GetWrapperFor(child);
}

- (BOOL)outlineView:(NSOutlineView *)outlineView isItemExpandable:(id)item
{
    if (!mBookmarks)
        return NO;
    
    if (!item)
        return YES; // The root node is always open.
    
    nsCOMPtr<nsIAtom> tagName;
    nsIContent* content = [item contentNode];
    content->GetTag(*getter_AddRefs(tagName));
    
    return (tagName == BookmarksService::gFolderAtom);
}

- (int)outlineView:(NSOutlineView *)outlineView numberOfChildrenOfItem:(id)item
{
    if (!mBookmarks)
        return 0;
  
    nsCOMPtr<nsIContent> content;
    if (!item)
        mBookmarks->GetRootContent(getter_AddRefs(content));
    else 
        content = [item contentNode];
    
    PRInt32 childCount;
    content->ChildCount(childCount);
    
    return childCount;
}

- (id)outlineView:(NSOutlineView *)outlineView objectValueForTableColumn:(NSTableColumn *)tableColumn byItem:(id)item
{
    NSString 					*columnName = [tableColumn identifier];
    NSMutableAttributedString 	*cellValue = [[NSMutableAttributedString alloc] init];
    NSFileWrapper				*fileWrapper = [[NSFileWrapper alloc] initRegularFileWithContents:nil];
    NSTextAttachment			*textAttachment = [[NSTextAttachment alloc] initWithFileWrapper:fileWrapper];
    NSMutableAttributedString   *attachmentAttrString = nil;
    NSCell 						*attachmentAttrStringCell;

    if ([columnName isEqualToString: @"name"]) {
        nsIContent* content = [item contentNode];
        nsAutoString nameAttr;
        content->GetAttr(kNameSpaceID_None, BookmarksService::gNameAtom, nameAttr);
        
        //Set cell's textual contents
        [cellValue replaceCharactersInRange:NSMakeRange(0, [cellValue length])
                                 withString:[NSString stringWithCharacters: nameAttr.get() length: nameAttr.Length()]];
        
        //Create an attributed string to hold the empty attachment, then release the components.
        attachmentAttrString = [[NSMutableAttributedString attributedStringWithAttachment:textAttachment] retain];
        [textAttachment release];
        [fileWrapper release];

        //Get the cell of the text attachment.
        attachmentAttrStringCell = (NSCell *)[(NSTextAttachment *)[attachmentAttrString attribute:NSAttachmentAttributeName
                                                                                          atIndex:0
                                                                                   effectiveRange:nil] attachmentCell];
        //Figure out which image to add, and set the cell's image.
        // Use the bookmark groups image for groups.
        if ([self outlineView:outlineView isItemExpandable:item]) {
          nsIContent* content = [item contentNode];
          nsCOMPtr<nsIDOMElement> elt(do_QueryInterface(content));
          nsAutoString group;
          elt->GetAttribute(NS_LITERAL_STRING("group"), group);
          if (!group.IsEmpty())
            [attachmentAttrStringCell setImage:[NSImage imageNamed:@"groupbookmark"]];
          else
            [attachmentAttrStringCell setImage:[NSImage imageNamed:@"folder"]];
        }
        else
          [attachmentAttrStringCell setImage:[NSImage imageNamed:@"smallbookmark"]];
        
        //Insert the image
        [cellValue replaceCharactersInRange:NSMakeRange(0, 0) withAttributedString:attachmentAttrString];
        
        //Tweak the baseline to vertically center the text.
        [cellValue addAttribute:NSBaselineOffsetAttributeName
                          value:[NSNumber numberWithFloat:-3.0]
                          range:NSMakeRange(0, 1)];
    }
    return cellValue;
}

- (void)outlineView:(NSOutlineView *)outlineView setObjectValue:(id)object forTableColumn:(NSTableColumn *)tableColumn byItem:(id)item
{
#if NOT_USED
  // ignore all this. It doesn't work, but i'm leaving it here just in case we ever try to turn 
  // this code back on. We have to remove the attributes from the string in order to correctly
  // set it in the DOM.
  
  NSString *columnName = [tableColumn identifier];
  if ( [columnName isEqualTo:@"name"] ) {
    // remove the attributes
    int strLen = [object length];
    NSMutableAttributedString *cellValue = [[NSMutableAttributedString alloc] initWithAttributedString:object];
    [cellValue removeAttribute:NSBaselineOffsetAttributeName range:NSMakeRange(0,1)];
    [cellValue removeAttribute:NSAttachmentAttributeName range:NSMakeRange(0,strLen)];

    // extract the unicode
    strLen = [cellValue length];
    PRUnichar* buffer = new PRUnichar[strLen + 1];
    buffer[strLen] = '\0';
    if ( !buffer )
      return;
    [cellValue getCharacters: buffer];
    nsAutoString nameAttr;
    nameAttr.Adopt(buffer);
    
    // stash it into the dom.
    nsIContent* content = [item contentNode];
    content->SetAttr(kNameSpaceID_None, BookmarksService::gNameAtom, nameAttr, PR_TRUE);
    
    [cellValue release];
  }
#endif
}

- (void)reloadDataForItem:(id)item reloadChildren: (BOOL)aReloadChildren
{
    printf("Reloading?\n");
    if (!item)
        [mOutlineView reloadData];
    else if ([mOutlineView isItemExpanded: item])
        [mOutlineView reloadItem: item reloadChildren: aReloadChildren];
}

- (BOOL)outlineView:(NSOutlineView*)outlineView acceptDrop:(id <NSDraggingInfo>)info item:(id)item childIndex:(int)index
{
  BookmarkItem* beforeItem = nil;
  nsCOMPtr<nsIDOMElement> beforeElt;
  nsCOMPtr<nsIDOMElement> folderElt;
  nsCOMPtr<nsIContent> folderContent;
  
  if (index == NSOutlineViewDropOnItemIndex)
    return NO;

  // get the folder element
  if (!item)
      mBookmarks->GetRootContent(getter_AddRefs(folderContent));
  else 
      folderContent = [item contentNode];
  folderElt = do_QueryInterface(folderContent);

  // get the element to insert before, if there is one
  PRInt32 childCount = 0;
  folderContent->ChildCount(childCount);
  if (index < childCount)
    beforeItem = [[outlineView dataSource] outlineView:outlineView child:index ofItem:item];
  if (beforeItem)
    beforeElt = do_QueryInterface([beforeItem contentNode]);
  
  // insert the dragged stuff into bookmarks
  BookmarksService::CompleteBookmarkDrag([info draggingPasteboard], folderElt, beforeElt, 
                                         BookmarksService::CHInsertBefore);

  return YES;
}

- (NSDragOperation)outlineView:(NSOutlineView*)outlineView validateDrop:(id <NSDraggingInfo>)info proposedItem:(id)item proposedChildIndex:(int)index
{
  if (index == NSOutlineViewDropOnItemIndex)
    return NSDragOperationNone;

  return NSDragOperationGeneric;
}

- (BOOL)outlineView:(NSOutlineView *)outlineView writeItems:(NSArray*)items toPasteboard:(NSPasteboard*)pboard
{
  NSMutableArray* contentIds = [NSMutableArray array];
  
  for (unsigned int i = 0; i < [items count]; ++i) {
    nsCOMPtr<nsIContent> content = [[items objectAtIndex:i] contentNode];
    PRUint32 contentId;
    content->GetContentID(&contentId);
    [contentIds addObject:[NSNumber numberWithInt:contentId]];
  }
  
  [pboard declareTypes:[NSArray arrayWithObject:@"MozBookmarkType"] owner:outlineView];
  [pboard setPropertyList:contentIds forType:@"MozBookmarkType"];

  return YES;
}


//
// beginRenameBookmark:
//
// Called to rename a bookmark. If there is only 1 row selected in the 
// outliner, show a sheet attached to the main browser window that has
// the selected item's name pre-filled.
//
-(IBAction)beginRenameBookmark:(id)aSender
{
  int index = [mOutlineView selectedRow];
  if (index == -1)
    return;
  if ([mOutlineView numberOfSelectedRows] == 1) {
    // get the name of the item from the content model so we don't have to worry about
    // the attributed string stored by the outliner
    BookmarkItem* item = [mOutlineView itemAtRow: index];
    nsAutoString nameAttr;
    [item contentNode]->GetAttr(kNameSpaceID_None, BookmarksService::gNameAtom, nameAttr);
  
    // stuff it into the string
    NSString* name = [NSString stringWithCharacters:nameAttr.get() length:nameAttr.Length()];
    [mRenameTextField setStringValue:name];
    
    // show the sheet
    [NSApp beginSheet: mRenameSheet
      modalForWindow: [mBrowserWindowController window] modalDelegate: nil
      didEndSelector: nil contextInfo: nil];
  }
}


//
// cancelRenameBookmarkSheet:
//
// User clicked cancel in the bookmarks rename sheet. Just bail and
// hide the sheet.
//
-(IBAction)cancelRenameBookmarkSheet:(id)sender
{
  [mRenameSheet orderOut:self];
  [NSApp endSheet:mRenameSheet returnCode:0];
}


//
// doRenameBookmarkSheet:
//
// User clicked ok in the bookmarks rename sheet. Grab the string out
// of the sheet's text field and stash it into the content model.
//
-(IBAction)doRenameBookmarkSheet:(id)sender
{
  [mRenameSheet orderOut:self];
  [NSApp endSheet:mRenameSheet returnCode:0];
  
  // extract the string from the text field into a unicode buffer
  unsigned int len = [[mRenameTextField stringValue] length];
  PRUnichar* buffer = new PRUnichar[len + 1];
  if (!buffer) 
    return;
  [[mRenameTextField stringValue] getCharacters:buffer];
  buffer[len] = (PRUnichar)'\0';
  
  // stuff it into our bookmarks item. |buff| takes ownership of |buffer| so
  // it doesn't have to be deleted manually
  BookmarkItem* item = [mOutlineView itemAtRow: [mOutlineView selectedRow]];
  nsXPIDLString buff; buff.Adopt(buffer);
  [item contentNode]->SetAttr(kNameSpaceID_None, BookmarksService::gNameAtom, buff, PR_TRUE);
  mBookmarks->BookmarkChanged([item contentNode]);
}

-(IBAction)openBookmarkInNewTab:(id)aSender
{
  int index = [mOutlineView selectedRow];
  if (index == -1)
    return;
  if ([mOutlineView numberOfSelectedRows] == 1) {
    nsCOMPtr<nsIPrefBranch> pref(do_GetService("@mozilla.org/preferences-service;1"));
    if (!pref)
        return; // Something bad happened if we can't get prefs.

    BookmarkItem* item = [mOutlineView itemAtRow: index];
    nsAutoString hrefAttr;
    [item contentNode]->GetAttr(kNameSpaceID_None, BookmarksService::gHrefAtom, hrefAttr);
  
    // stuff it into the string
    NSString* hrefStr = [NSString stringWithCharacters:hrefAttr.get() length:hrefAttr.Length()];
    NSURL* urlToLoad = [NSURL URLWithString: hrefStr];

    PRBool loadInBackground;
    pref->GetBoolPref("browser.tabs.loadInBackground", &loadInBackground);

    [mBrowserWindowController openNewTabWithURL: urlToLoad loadInBackground: loadInBackground];
  }
}

-(IBAction)openBookmarkInNewWindow:(id)aSender
{
  int index = [mOutlineView selectedRow];
  if (index == -1)
    return;
  if ([mOutlineView numberOfSelectedRows] == 1) {
    BookmarkItem* item = [mOutlineView itemAtRow: index];
    nsAutoString hrefAttr;
    [item contentNode]->GetAttr(kNameSpaceID_None, BookmarksService::gHrefAtom, hrefAttr);
  
    // stuff it into the string
    NSString* hrefStr = [NSString stringWithCharacters:hrefAttr.get() length:hrefAttr.Length()];
    NSURL* urlToLoad = [NSURL URLWithString: hrefStr];

    nsAutoString group;
    nsCOMPtr<nsIDOMElement> elt(do_QueryInterface([item contentNode]));
    elt->GetAttribute(NS_LITERAL_STRING("group"), group);
    if (group.IsEmpty()) 
      [mBrowserWindowController openNewWindowWithURL: urlToLoad loadInBackground: NO];
    else
      [mBrowserWindowController openNewWindowWithGroup: elt loadInBackground: NO];
  }
}

-(void)openBookmarkGroup:(id)aTabView groupElement:(nsIDOMElement*)aFolder
{
  mBookmarks->OpenBookmarkGroup(aTabView, aFolder);
}

-(BOOL)validateMenuItem:(NSMenuItem*)aMenuItem
{
  int index = [mOutlineView selectedRow];
  if (index == -1)
    return NO;

  BookmarkItem* item = [mOutlineView itemAtRow: index];
  BOOL isBookmark = [mOutlineView isExpandable:item] == NO;
  
  nsAutoString group;
  nsCOMPtr<nsIDOMElement> elt(do_QueryInterface([item contentNode]));
  elt->GetAttribute(NS_LITERAL_STRING("group"), group);
  BOOL isGroup = !group.IsEmpty();

  if (([aMenuItem action] == @selector(openBookmarkInNewWindow:))) {
    // Bookmarks and Bookmark Groups can be opened in a new window
    return (isBookmark || isGroup);
  }
  else if (([aMenuItem action] == @selector(openBookmarkInNewTab:))) {
    // Only Bookmarks can be opened in new tabs
    return isBookmark;
  }
  return YES;
}

@end

@implementation BookmarkItem
-(nsIContent*)contentNode
{
    return mContentNode;
}

-(void)setContentNode: (nsIContent*)aContentNode
{
    mContentNode = aContentNode;
}

- (id)copyWithZone:(NSZone *)aZone
{
    BookmarkItem* copy = [[[self class] allocWithZone: aZone] init];
    [copy setContentNode: mContentNode];
    return copy;
}

@end

// Helper for stripping whitespace
static void
StripWhitespaceNodes(nsIContent* aElement)
{
    PRInt32 childCount;
    aElement->ChildCount(childCount);
    for (PRInt32 i = 0; i < childCount; i++) {
        nsCOMPtr<nsIContent> child;
        aElement->ChildAt(i, *getter_AddRefs(child));
        nsCOMPtr<nsITextContent> text = do_QueryInterface(child);
        if (text) {
            PRBool isEmpty;
            text->IsOnlyWhitespace(&isEmpty);
            if (isEmpty) {
                // This node contained nothing but whitespace.
                // Remove it from the content model.
                aElement->RemoveChildAt(i, PR_TRUE);
                i--; // Decrement our count, since we just removed this child.
                childCount--; // Also decrement our total count.
            }
        }
        else StripWhitespaceNodes(child);
    }
}

PRUint32 BookmarksService::gRefCnt = 0;
nsIDocument* BookmarksService::gBookmarks = nsnull;
NSMutableDictionary* BookmarksService::gDictionary = nil;
MainController* BookmarksService::gMainController = nil;
NSMenu* BookmarksService::gBookmarksMenu = nil;
nsIDOMElement* BookmarksService::gToolbarRoot = nsnull;
nsIAtom* BookmarksService::gFolderAtom = nsnull;
nsIAtom* BookmarksService::gBookmarkAtom = nsnull;
nsIAtom* BookmarksService::gHrefAtom = nsnull;
nsIAtom* BookmarksService::gNameAtom = nsnull;
nsVoidArray* BookmarksService::gInstances = nsnull;
int BookmarksService::CHInsertNone = 0;
int BookmarksService::CHInsertInto = 1;
int BookmarksService::CHInsertBefore = 2;
int BookmarksService::CHInsertAfter = 3;

BookmarksService::BookmarksService(BookmarksDataSource* aDataSource)
{
  mDataSource = aDataSource;
  mToolbar = nil;
}

BookmarksService::BookmarksService(CHBookmarksToolbar* aToolbar)
{
  mDataSource = nil;
  mToolbar = aToolbar;
}

BookmarksService::~BookmarksService()
{
}

void
BookmarksService::GetRootContent(nsIContent** aResult)
{
    *aResult = nsnull;
    if (gBookmarks) {
        nsCOMPtr<nsIDOMElement> elt;
        nsCOMPtr<nsIDOMDocument> domDoc(do_QueryInterface(gBookmarks));
        domDoc->GetDocumentElement(getter_AddRefs(elt));
        elt->QueryInterface(NS_GET_IID(nsIContent), (void**)aResult); // Addref happens here.
    }
}

BookmarkItem*
BookmarksService::GetWrapperFor(nsIContent* aContent)
{
    if (!gDictionary)
        gDictionary = [[NSMutableDictionary alloc] initWithCapacity: 30];
    
    PRUint32 contentID;
    aContent->GetContentID(&contentID);
    
    BookmarkItem* item = [gDictionary objectForKey: [NSNumber numberWithInt: contentID]];
    if (item)
        return item;
    else {
        // Create an item.
        item = [[[BookmarkItem alloc] init] autorelease]; // The dictionary retains us.
        [item setContentNode: aContent];
        [gDictionary setObject: item forKey: [NSNumber numberWithInt: contentID]];
    }
    return item;
}

NSMenu*
BookmarksService::LocateMenu(nsIContent* aContent)
{
  nsCOMPtr<nsIContent> parent;
  aContent->GetParent(*getter_AddRefs(parent));
  if (!parent) {
    return BookmarksService::gBookmarksMenu;
  }
  
  NSMenu* parentMenu = LocateMenu(parent);
  
  PRUint32 contentID;
  aContent->GetContentID(&contentID);

  NSMenuItem* childMenu = [parentMenu itemWithTag: contentID];
  return [childMenu submenu];
}

void
BookmarksService::BookmarkAdded(nsIContent* aContainer, nsIContent* aChild)
{
  if (!gInstances || !gDictionary)
    return;

  PRInt32 count = gInstances->Count();
  for (PRInt32 i = 0; i < count; i++) {
    BookmarksService* instance = (BookmarksService*)gInstances->ElementAt(i);

    if (instance->mDataSource) {
      // We're a tree view.
      nsCOMPtr<nsIContent> parent;
      aContainer->GetParent(*getter_AddRefs(parent));

      BookmarkItem* item = nil;
      if (parent)
        // We're not the root.
        item = GetWrapperFor(aContainer);

      [(instance->mDataSource) reloadDataForItem: item reloadChildren: YES];
    }
    else if (instance->mToolbar) {
      // We're a personal toolbar.
      nsCOMPtr<nsIDOMElement> parentElt(do_QueryInterface(aContainer));
      if (parentElt == gToolbarRoot) {
        // We only care about changes that occur to the personal toolbar's immediate
        // children.
        PRInt32 index = -1;
        aContainer->IndexOf(aChild, index);
        nsCOMPtr<nsIDOMElement> elt(do_QueryInterface(aChild));
        [(instance->mToolbar) addButton: elt atIndex: index];
      }
    }
    else {
      // We're the menu.
      PRInt32 index = -1;
      aContainer->IndexOf(aChild, index);
      NSMenu* menu = LocateMenu(aContainer);
      AddMenuBookmark(menu, aContainer, aChild, index);
    }
  }
  
  FlushBookmarks();  
}

void
BookmarksService::BookmarkChanged(nsIContent* aItem)
{
  if (!gInstances || !gDictionary)
    return;

  PRInt32 count = gInstances->Count();
  for (PRInt32 i = 0; i < count; i++) {
    BookmarksService* instance = (BookmarksService*)gInstances->ElementAt(i);
   
    if (instance->mDataSource) {
      BookmarkItem* item = GetWrapperFor(aItem);
      [(instance->mDataSource) reloadDataForItem: item reloadChildren: NO];
    }
  }

  FlushBookmarks();  
}

void
BookmarksService::BookmarkRemoved(nsIContent* aContainer, nsIContent* aChild)
{
  if (!gInstances)
    return;

  PRInt32 count = gInstances->Count();
  for (PRInt32 i = 0; i < count; i++) {
    BookmarksService* instance = (BookmarksService*)gInstances->ElementAt(i);

    if (instance->mDataSource) {
      // We're a tree view.
      nsCOMPtr<nsIContent> parent;
      aContainer->GetParent(*getter_AddRefs(parent));

      BookmarkItem* item = nil;
      if (parent)
        // We're not the root.
        item = GetWrapperFor(aContainer);

      [(instance->mDataSource) reloadDataForItem: item reloadChildren: YES];
    }
    else if (instance->mToolbar) {
      // We're a personal toolbar.
      nsCOMPtr<nsIDOMElement> parentElt(do_QueryInterface(aContainer));
      if (parentElt == gToolbarRoot) {
        // We only care about changes that occur to the personal toolbar's immediate
        // children.
        nsCOMPtr<nsIDOMElement> childElt(do_QueryInterface(aChild));
        [(instance->mToolbar) removeButton: childElt];
      }
    }    
    else {
      // We're the menu.
      NSMenu* menu = LocateMenu(aContainer);
      PRUint32 contentID;
      aChild->GetContentID(&contentID);
      NSMenuItem* childItem = [menu itemWithTag: contentID];
      [menu removeItem: childItem];
    }
  }

  FlushBookmarks(); 
}

void
BookmarksService::AddObserver()
{
    gRefCnt++;
    if (gRefCnt == 1) {
        gBookmarkAtom = NS_NewAtom("bookmark");
        gFolderAtom = NS_NewAtom("folder");
        gNameAtom = NS_NewAtom("name");
        gHrefAtom = NS_NewAtom("href");
        gInstances = new nsVoidArray();
                
        nsCOMPtr<nsIFile> profileDir;
        NS_GetSpecialDirectory(NS_APP_USER_PROFILE_50_DIR, getter_AddRefs(profileDir));
        profileDir->Append(NS_LITERAL_STRING("bookmarks.xml"));
    
        nsCAutoString bookmarksFileURL;
        NS_GetURLSpecFromFile(profileDir, bookmarksFileURL);
        
        nsCOMPtr<nsIURI> uri;
        NS_NewURI(getter_AddRefs(uri), bookmarksFileURL.get());
    
        nsCOMPtr<nsIXBLService> xblService(do_GetService("@mozilla.org/xbl;1"));    
        xblService->FetchSyncXMLDocument(uri, &gBookmarks); // The addref is here.
        
        nsCOMPtr<nsIContent> rootNode;
        GetRootContent(getter_AddRefs(rootNode));
        StripWhitespaceNodes(rootNode);
    }
    
    gInstances->AppendElement(this);
}

void
BookmarksService::RemoveObserver()
{
    if (gRefCnt == 0)
        return;
 
    gInstances->RemoveElement(this);
     
    gRefCnt--;
    if (gRefCnt == 0) {
        NS_IF_RELEASE(gBookmarks);
        NS_RELEASE(gBookmarkAtom);
        NS_RELEASE(gFolderAtom);
        NS_RELEASE(gNameAtom);
        NS_RELEASE(gHrefAtom);
        [gDictionary release];
    }
}

void
BookmarksService::AddBookmarkToFolder(nsString& aURL, nsString& aTitle, nsIDOMElement* aFolder, nsIDOMElement* aBeforeElt)
{
  // XXX if no folder provided, default to root folder
  if (!aFolder) return;
  
  nsCOMPtr<nsIDOMDocument> domDoc(do_QueryInterface(gBookmarks));
  nsCOMPtr<nsIDOMElement> elt;
  domDoc->CreateElementNS(NS_LITERAL_STRING("http://chimera.mozdev.org/bookmarks/"),
                          NS_LITERAL_STRING("bookmark"),
                          getter_AddRefs(elt));

  elt->SetAttribute(NS_LITERAL_STRING("name"), aTitle);
  elt->SetAttribute(NS_LITERAL_STRING("href"), aURL);

  MoveBookmarkToFolder(elt, aFolder, aBeforeElt);
}

void
BookmarksService::MoveBookmarkToFolder(nsIDOMElement* aBookmark, nsIDOMElement* aFolder, nsIDOMElement* aBeforeElt)
{
  if (!aBookmark || !aFolder) return;
  
  nsCOMPtr<nsIDOMNode> oldParent;
  aBookmark->GetParentNode(getter_AddRefs(oldParent));

  nsCOMPtr<nsIDOMNode> dummy;
  if (oldParent) {
    nsCOMPtr<nsIDOMNode> bookmarkNode = do_QueryInterface(aBookmark);
    oldParent->RemoveChild(bookmarkNode, getter_AddRefs(dummy));
  }

  if (aBeforeElt) {
    aFolder->InsertBefore(aBookmark, aBeforeElt, getter_AddRefs(dummy));
  } else {
    aFolder->AppendChild(aBookmark, getter_AddRefs(dummy));
  }
  
  nsCOMPtr<nsIContent> childContent(do_QueryInterface(aBookmark));
  nsCOMPtr<nsIContent> parentContent(do_QueryInterface(aFolder));

  if (oldParent) {
    nsCOMPtr<nsIContent> oldParentContent(do_QueryInterface(oldParent));
    BookmarkRemoved(oldParentContent, childContent);
  }
  
  BookmarkAdded(parentContent, childContent);
}

void
BookmarksService::DeleteBookmark(nsIDOMElement* aBookmark)
{
  if (!aBookmark) return;
  
  nsCOMPtr<nsIDOMNode> oldParent;
  aBookmark->GetParentNode(getter_AddRefs(oldParent));

  if (oldParent) {
    nsCOMPtr<nsIDOMNode> dummy;
    nsCOMPtr<nsIDOMNode> bookmarkNode = do_QueryInterface(aBookmark);
    oldParent->RemoveChild(bookmarkNode, getter_AddRefs(dummy));

    nsCOMPtr<nsIContent> childContent(do_QueryInterface(aBookmark));
    nsCOMPtr<nsIContent> oldParentContent(do_QueryInterface(oldParent));
    BookmarkRemoved(oldParentContent, childContent);
  }
}

void
BookmarksService::FlushBookmarks()
{
    nsCOMPtr<nsIFile> bookmarksFile;
    NS_GetSpecialDirectory(NS_APP_USER_PROFILE_50_DIR, getter_AddRefs(bookmarksFile));
    bookmarksFile->Append(NS_LITERAL_STRING("bookmarks.xml"));

    nsCOMPtr<nsIOutputStream> outputStream;
    NS_NewLocalFileOutputStream(getter_AddRefs(outputStream), bookmarksFile);

    nsCOMPtr<nsIDOMDocument> domDoc(do_QueryInterface(gBookmarks));
    
    nsCOMPtr<nsIDOMSerializer> domSerializer(do_CreateInstance(NS_XMLSERIALIZER_CONTRACTID));
    domSerializer->SerializeToStream(domDoc, outputStream, nsnull);
}

void BookmarksService::EnsureToolbarRoot()
{
  if (gToolbarRoot)
    return;

  nsCOMPtr<nsIDOMDocument> domDoc(do_QueryInterface(gBookmarks));
  nsCOMPtr<nsIDOMElement> rootElt;
  domDoc->GetDocumentElement(getter_AddRefs(rootElt));
  
  nsCOMPtr<nsIDOMNode> child;
  rootElt->GetFirstChild(getter_AddRefs(child));
  nsAutoString typeValue;
  while (child) {
    nsCOMPtr<nsIDOMElement> childElt(do_QueryInterface(child));
    if (childElt) {
      childElt->GetAttribute(NS_LITERAL_STRING("type"), typeValue);
      if (typeValue.Equals(NS_LITERAL_STRING("toolbar")))
        gToolbarRoot = childElt;
    }
    
    nsCOMPtr<nsIDOMNode> temp;
    child->GetNextSibling(getter_AddRefs(temp));
    child = temp;
  }

  if (!gToolbarRoot) {
    printf("Repairing personal toolbar.\n");
    nsCOMPtr<nsIDOMElement> elt;
    domDoc->CreateElementNS(NS_LITERAL_STRING("http://chimera.mozdev.org/bookmarks/"),
                            NS_LITERAL_STRING("folder"),
                            getter_AddRefs(elt));

    elt->SetAttribute(NS_LITERAL_STRING("name"), NS_LITERAL_STRING("Toolbar Bookmarks"));
    elt->SetAttribute(NS_LITERAL_STRING("type"), NS_LITERAL_STRING("toolbar"));

    nsCOMPtr<nsIDOMNode> dummy;
    rootElt->AppendChild(elt, getter_AddRefs(dummy));
    gToolbarRoot = elt;
  }
}

static
void RecursiveAddBookmarkConstruct(NSPopUpButton* aPopup, NSMenu* aMenu, int aTagToMatch, int depth = 0)
{
  // Get the menu item children.
  NSArray* children = [aMenu itemArray];
  int startPosition = 0;
  if (aMenu == BookmarksService::gBookmarksMenu)
    startPosition = 3;

  int count = [children count];
  for (int i = startPosition; i < count; ++i) {
    NSMenuItem* menuItem = [children objectAtIndex: i];
    NSMenu* submenu = [menuItem submenu];
    if (submenu) {
      // This is a folder.  Add it to our list and then recur. Indent it
      // the apropriate depth for readability in the menu.
      NSMutableString *title = [NSMutableString stringWithString:[menuItem title]];
      for (int j = 0; j <= depth; ++j) 
        [title insertString:@"    " atIndex: 0];
	  
      [aPopup addItemWithTitle: title];
      NSMenuItem* lastItem = [aPopup lastItem];
      if ([menuItem tag] == aTagToMatch)
        [aPopup selectItem: lastItem];
      
      [lastItem setTag: [menuItem tag]];
      RecursiveAddBookmarkConstruct(aPopup, submenu, aTagToMatch, depth+1);
    }
  }
}

void
BookmarksService::ConstructAddBookmarkFolderList(NSPopUpButton* aPopup, BookmarkItem* aItem)
{
  [aPopup removeAllItems];
  [aPopup addItemWithTitle: [gBookmarksMenu title]];
  NSMenuItem* lastItem = [aPopup lastItem];
  [lastItem setTag: -1];
  int tag = -1;
  if (aItem) {
    nsIContent* content = [aItem contentNode];
    PRUint32 utag;
    content->GetContentID(&utag);
    tag = (int)utag;
  }
  RecursiveAddBookmarkConstruct(aPopup, gBookmarksMenu, tag);
}

void
BookmarksService::GetTitleAndHrefForBrowserView(id aBrowserView, nsString& aTitle, nsString& aHref)
{
  nsCOMPtr<nsIWebBrowser> webBrowser = getter_AddRefs([aBrowserView getWebBrowser]);
  nsCOMPtr<nsIDOMWindow> window;
  webBrowser->GetContentDOMWindow(getter_AddRefs(window));
  nsCOMPtr<nsIDOMDocument> htmlDoc;
  window->GetDocument(getter_AddRefs(htmlDoc));
  nsCOMPtr<nsIDocument> pageDoc(do_QueryInterface(htmlDoc));

  if (pageDoc) {
    nsCOMPtr<nsIURI> url;
    pageDoc->GetDocumentURL(getter_AddRefs(url));
    nsCAutoString spec;
    url->GetSpec(spec);
    aHref.AssignWithConversion(spec.get());
  }

  nsCOMPtr<nsIDOMHTMLDocument> htmlDocument(do_QueryInterface(htmlDoc));
  if (htmlDocument)
    htmlDocument->GetTitle(aTitle);
  if (aTitle.IsEmpty())
    aTitle = aHref;  
}

void
BookmarksService::ConstructBookmarksMenu(NSMenu* aMenu, nsIContent* aContent)
{
    nsCOMPtr<nsIContent> content = aContent;
    if (!content) {
        GetRootContent(getter_AddRefs(content));
        GetWrapperFor(content);
        gBookmarksMenu = aMenu;
    }
    
    // Now walk our children, and for folders also recur into them.
    PRInt32 childCount;
    content->ChildCount(childCount);
    
    for (PRInt32 i = 0; i < childCount; i++) {
      nsCOMPtr<nsIContent> child;
      content->ChildAt(i, *getter_AddRefs(child));
      AddMenuBookmark(aMenu, content, child, -1);
    }
}

void
BookmarksService::AddMenuBookmark(NSMenu* aMenu, nsIContent* aParent, nsIContent* aChild, PRInt32 aIndex)
{
  nsAutoString name;
  aChild->GetAttr(kNameSpaceID_None, gNameAtom, name);
  NSString* title = [NSString stringWithCharacters: name.get() length: name.Length()];

  // Create a menu or menu item for the child.
  NSMenuItem* menuItem = [[[NSMenuItem alloc] initWithTitle: title action: NULL keyEquivalent: @""] autorelease];
  GetWrapperFor(aChild);

  if (aIndex == -1)
    [aMenu addItem: menuItem];
  else
    [aMenu insertItem: menuItem atIndex: aIndex];
  
  nsCOMPtr<nsIAtom> tagName;
  aChild->GetTag(*getter_AddRefs(tagName));

  nsAutoString group;
  nsCOMPtr<nsIDOMElement> elt(do_QueryInterface(aChild));
  elt->GetAttribute(NS_LITERAL_STRING("group"), group);

  if (group.IsEmpty() && tagName == gFolderAtom) {
    NSMenu* menu = [[[NSMenu alloc] initWithTitle: title] autorelease];
    [aMenu setSubmenu: menu forItem: menuItem];
    [menu setAutoenablesItems: NO];
    [menuItem setImage: [NSImage imageNamed:@"folder"]];
    ConstructBookmarksMenu(menu, aChild);
  }
  else {
    if (group.IsEmpty())
      [menuItem setImage: [NSImage imageNamed:@"smallbookmark"]];
    else
      [menuItem setImage: [NSImage imageNamed:@"groupbookmark"]];
    
    [menuItem setTarget: gMainController];
    [menuItem setAction: @selector(openMenuBookmark:)];
  }

  PRUint32 contentID;
  aChild->GetContentID(&contentID);
  [menuItem setTag: contentID];
}

void 
BookmarksService::OpenMenuBookmark(BrowserWindowController* aController, id aMenuItem)
{
  // Get the corresponding bookmark item.
  BookmarkItem* item = [gDictionary objectForKey: [NSNumber numberWithInt: [aMenuItem tag]]];

  // Get the content node.
  nsIContent* content = [item contentNode];
  nsCOMPtr<nsIDOMElement> elt(do_QueryInterface(content));
  nsAutoString group;
  elt->GetAttribute(NS_LITERAL_STRING("group"), group);
  if (!group.IsEmpty())
    return OpenBookmarkGroup([aController getTabBrowser], elt);
  
  // Get the href attribute.  This is the URL we want to load.
  nsAutoString href;
  content->GetAttr(kNameSpaceID_None, gHrefAtom, href);
  if (href.IsEmpty())
    return;

  NSString* url = [NSString stringWithCharacters: href.get() length: href.Length()];

  // Now load the URL in the window.
  [aController loadURL:[NSURL URLWithString: url]];

  // Focus and activate our content area.
  [[[aController getBrowserWrapper] getBrowserView] setActive: YES];
}

static void GetImportTitle(nsIDOMElement* aSrc, nsString& aTitle)
{
  nsCOMPtr<nsIDOMNode> curr;
  aSrc->GetFirstChild(getter_AddRefs(curr));
  while (curr) {
    nsCOMPtr<nsIDOMCharacterData> charData(do_QueryInterface(curr));
    if (charData) {
      nsAutoString data;
      charData->GetData(data);
      aTitle += data;
    }
    else {
      // Handle Omniweb's nesting of <a> inside <h3> for its folders.
      nsCOMPtr<nsIDOMElement> elt(do_QueryInterface(curr));
      if (elt) {
        nsAutoString localName;
        elt->GetLocalName(localName);
        ToLowerCase(localName);
        if (localName.Equals(NS_LITERAL_STRING("a"))) {
          aTitle = NS_LITERAL_STRING("");
          return GetImportTitle(elt, aTitle);
        }
      }
    }
    
    nsCOMPtr<nsIDOMNode> temp = curr;
    temp->GetNextSibling(getter_AddRefs(curr));
  }
}

static void CreateBookmark(nsIDOMElement* aSrc, nsIDOMElement* aDst,
                           nsIDOMDocument* aDstDoc, PRBool aIsFolder,
                           nsIDOMElement** aResult)
{
  nsAutoString tagName(NS_LITERAL_STRING("bookmark"));
  if (aIsFolder)
    tagName = NS_LITERAL_STRING("folder");

  aDstDoc->CreateElementNS(NS_LITERAL_STRING("http://chimera.mozdev.org/bookmarks/"),
                           tagName,
                           aResult); // Addref happens here.

  nsAutoString title;
  GetImportTitle(aSrc, title);
  (*aResult)->SetAttribute(NS_LITERAL_STRING("name"), title);

  if (!aIsFolder) {
    nsAutoString href;
    aSrc->GetAttribute(NS_LITERAL_STRING("href"), href);
    (*aResult)->SetAttribute(NS_LITERAL_STRING("href"), href);
  }

  nsCOMPtr<nsIDOMNode> dummy;
  aDst->AppendChild(*aResult, getter_AddRefs(dummy));
}

static void AddImportedBookmarks(nsIDOMElement* aSrc, nsIDOMElement* aDst, nsIDOMDocument* aDstDoc,
                                 PRInt32& aBookmarksType)
{
  nsAutoString localName;
  aSrc->GetLocalName(localName);
  ToLowerCase(localName);
  nsCOMPtr<nsIDOMElement> newBookmark;
  if (localName.Equals(NS_LITERAL_STRING("bookmarkinfo")))
    aBookmarksType = 1; // Omniweb.
  else if (localName.Equals(NS_LITERAL_STRING("dt"))) {
    // We have found either a folder or a leaf.
    nsCOMPtr<nsIDOMNode> curr;
    aSrc->GetFirstChild(getter_AddRefs(curr));
    while (curr) {
      nsCOMPtr<nsIDOMElement> childElt(do_QueryInterface(curr));
      if (childElt) {
        childElt->GetLocalName(localName);
        ToLowerCase(localName);
        if (localName.Equals(NS_LITERAL_STRING("a"))) {
          // Guaranteed to be a bookmark in IE.  Could be either in Omniweb.
          nsCOMPtr<nsIDOMElement> dummy;
          CreateBookmark(childElt, aDst, aDstDoc, PR_FALSE, getter_AddRefs(dummy));
        }
        // Ignore the H3 we encounter.  This will be dealt with later.
      }
      nsCOMPtr<nsIDOMNode> temp = curr;
      temp->GetNextSibling(getter_AddRefs(curr));
    }
  }
  else if (localName.Equals(NS_LITERAL_STRING("dl"))) {
    // The children of a folder.  Recur inside.
    // Locate the parent to create the folder.
    nsCOMPtr<nsIDOMNode> node;
    aSrc->GetPreviousSibling(getter_AddRefs(node));
    nsCOMPtr<nsIDOMElement> folderElt(do_QueryInterface(node));
    if (folderElt) {
      // Make sure it's an H3 folder in Mozilla and IE.  In Mozilla it will probably have an ID.
      PRBool hasID;
      folderElt->HasAttribute(NS_LITERAL_STRING("ID"), &hasID);
      if (aBookmarksType != 1) {
        if (hasID)
          aBookmarksType = 2; // Mozilla
        else
          aBookmarksType = 0; // IE
      }
      nsAutoString localName;
      folderElt->GetLocalName(localName);
      ToLowerCase(localName);
      if (localName.Equals(NS_LITERAL_STRING("h3")))
        CreateBookmark(folderElt, aDst, aDstDoc, PR_TRUE, getter_AddRefs(newBookmark));
    }
    if (!newBookmark)
      newBookmark = aDst;
    // Recur over all our children.
    nsCOMPtr<nsIDOMNode> curr;
    aSrc->GetFirstChild(getter_AddRefs(curr));
    while (curr) {
      nsCOMPtr<nsIDOMElement> elt(do_QueryInterface(curr));
      if (elt)
        AddImportedBookmarks(elt, newBookmark, aDstDoc, aBookmarksType);
      nsCOMPtr<nsIDOMNode> temp = curr;
      temp->GetNextSibling(getter_AddRefs(curr));
    }
  }
  else {
    // Recur over all our children.
    nsCOMPtr<nsIDOMNode> curr;
    aSrc->GetFirstChild(getter_AddRefs(curr));
    while (curr) {
      nsCOMPtr<nsIDOMElement> elt(do_QueryInterface(curr));
      if (elt)
        AddImportedBookmarks(elt, aDst, aDstDoc, aBookmarksType);
      nsCOMPtr<nsIDOMNode> temp = curr;
      temp->GetNextSibling(getter_AddRefs(curr));
    }
  }
}

void
BookmarksService::ImportBookmarks(nsIDOMHTMLDocument* aHTMLDoc)
{
  nsCOMPtr<nsIDOMElement> domElement;
  aHTMLDoc->GetDocumentElement(getter_AddRefs(domElement));

  nsCOMPtr<nsIDOMElement> elt;
  nsCOMPtr<nsIDOMDocument> domDoc(do_QueryInterface(gBookmarks));
  domDoc->GetDocumentElement(getter_AddRefs(elt));

  // Create the root by hand.
  nsCOMPtr<nsIDOMElement> childElt;
  domDoc->CreateElementNS(NS_LITERAL_STRING("http://chimera.mozdev.org/bookmarks/"),
                          NS_LITERAL_STRING("folder"),
                          getter_AddRefs(childElt));
  nsCOMPtr<nsIDOMNode> dummy;
  elt->AppendChild(childElt, getter_AddRefs(dummy));
  
  // Now crawl through the file and look for <DT> elements.  They signify folders
  // or leaves.
  PRInt32 bookmarksType = 0; // Assume IE.
  AddImportedBookmarks(domElement, childElt, domDoc, bookmarksType);

  if (bookmarksType == 0)
    childElt->SetAttribute(NS_LITERAL_STRING("name"), NS_LITERAL_STRING("Internet Explorer Favorites"));
  else if (bookmarksType == 1)
    childElt->SetAttribute(NS_LITERAL_STRING("name"), NS_LITERAL_STRING("Omniweb Favorites"));
  else if (bookmarksType == 2)
    childElt->SetAttribute(NS_LITERAL_STRING("name"), NS_LITERAL_STRING("Mozilla/Netscape Favorites"));

  // Save out the file.
  FlushBookmarks();
  
  // Now do a notification that the root Favorites folder got added.  This
  // will update all our views.
  nsCOMPtr<nsIContent> parentContent(do_QueryInterface(elt));
  nsCOMPtr<nsIContent> childContent(do_QueryInterface(childElt));
  BookmarkAdded(parentContent, childContent);
}

void
BookmarksService::OpenBookmarkGroup(id aTabView, nsIDOMElement* aFolder)
{
  // We might conceivably have to make new tabs in order to load all
  // the items in the group.
  int currentIndex = 0;
  int total = [aTabView numberOfTabViewItems];
  nsCOMPtr<nsIDOMNode> child;
  aFolder->GetFirstChild(getter_AddRefs(child));
  while (child) {
    nsCOMPtr<nsIDOMElement> elt(do_QueryInterface(child));
    if (elt) {
      nsAutoString href;
      elt->GetAttribute(NS_LITERAL_STRING("href"), href);
      if (!href.IsEmpty()) {
        NSString* url = [NSString stringWithCharacters: href.get() length: href.Length()];
        NSTabViewItem* tabViewItem = nil;
        if (currentIndex >= total) {
          // We need to make a new tab.
          tabViewItem = [[[NSTabViewItem alloc] initWithIdentifier: nil] autorelease];
          CHBrowserWrapper* newView = [[[CHBrowserWrapper alloc] initWithTab: tabViewItem andWindow: [aTabView window]] autorelease];
          [tabViewItem setLabel: @"Untitled"];
          [tabViewItem setView: newView];
          [aTabView addTabViewItem: tabViewItem];
        }
        else
          tabViewItem = [aTabView tabViewItemAtIndex: currentIndex];

        [[[tabViewItem view] getBrowserView] loadURI:[NSURL URLWithString: url]
                                               flags: NSLoadFlagsNone];
      }
    }
    
    nsCOMPtr<nsIDOMNode> temp = child;
    temp->GetNextSibling(getter_AddRefs(child));
    currentIndex++;
  }

  // Select and activate the first tab.
  [aTabView selectTabViewItemAtIndex: 0];
  [[[[aTabView tabViewItemAtIndex: 0] view] getBrowserView] setActive: YES];
}

NSImage*
BookmarksService::CreateIconForBookmark(nsIDOMElement* aElement)
{
  nsCOMPtr<nsIAtom> tagName;
  nsCOMPtr<nsIContent> content = do_QueryInterface(aElement);
  content->GetTag(*getter_AddRefs(tagName));
  if (tagName == BookmarksService::gFolderAtom)
    return [NSImage imageNamed:@"folder"];
    
  nsAutoString group;
  aElement->GetAttribute(NS_LITERAL_STRING("group"), group);
  if (!group.IsEmpty())
    return [NSImage imageNamed:@"smallgroup"];
  
  return [NSImage imageNamed:@"groupbookmark"];
}

void
BookmarksService::DragBookmark(nsIDOMElement* aElement, NSView* aView, NSEvent* aEvent)
{
  NSPasteboard *pboard;
  NSString* title;
  
  nsCOMPtr<nsIContent> content = do_QueryInterface(aElement);
  PRUint32 contentId;
  content->GetContentID(&contentId);
  
  pboard = [NSPasteboard pasteboardWithName:NSDragPboard];
  [pboard declareTypes:[NSArray arrayWithObject:@"MozBookmarkType"] owner:aView];
  [pboard setPropertyList:[NSArray arrayWithObject:[NSNumber numberWithInt:contentId]] forType:@"MozBookmarkType"];
  
  nsAutoString nameStr;
  aElement->GetAttribute(NS_LITERAL_STRING("name"), nameStr);
  title = [NSString stringWithCharacters: nameStr.get() length: nameStr.Length()];
  
  [aView dragImage: [MainController createImageForDragging: CreateIconForBookmark(aElement) title:title]
                    at:NSMakePoint(0,0) offset:NSMakeSize(0,0)
                    event:aEvent pasteboard:pboard source:aView slideBack:YES];
}

void
BookmarksService::CompleteBookmarkDrag(NSPasteboard* aPasteboard, nsIDOMElement* aFolderElt,
                                       nsIDOMElement* aBeforeElt, int aPosition)
{
  NSArray* contentIds;
  
  nsCOMPtr<nsIDOMElement> beforeElt = aBeforeElt;
  if (aPosition == BookmarksService::CHInsertAfter && aBeforeElt) {
    nsCOMPtr<nsIDOMNode> beforeNode;
    aBeforeElt->GetNextSibling(getter_AddRefs(beforeNode));
    beforeElt = do_QueryInterface(beforeNode);
  }
  
  if (aPosition == BookmarksService::CHInsertInto) {
    aFolderElt = aBeforeElt;
    beforeElt = nsnull;
  }
    
  // check for recognized drag types
  contentIds = [aPasteboard propertyListForType: @"MozBookmarkType"];
  if (contentIds) {
    // drag type is chimera bookmarks
    for (unsigned int i = 0; i < [contentIds count]; ++i) {
      BookmarkItem* item = [gDictionary objectForKey: [contentIds objectAtIndex:i]];
      nsCOMPtr<nsIDOMElement> bookmarkElt = do_QueryInterface([item contentNode]);
      MoveBookmarkToFolder(bookmarkElt, aFolderElt, beforeElt);
    }
  } else {
    // add bookmark for chimera url type
    NSDictionary* data = [aPasteboard propertyListForType: @"MozURLType"];
    nsAutoString url; url.AssignWithConversion([[data objectForKey:@"url"] cString]);
    nsAutoString title; title.AssignWithConversion([[data objectForKey:@"title"] cString]);
    
    AddBookmarkToFolder(url, title, aFolderElt, beforeElt);
  }
}

