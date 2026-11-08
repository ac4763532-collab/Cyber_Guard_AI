/**
 * CyberGuard AI — Modal (Dialog) Component
 * ============================================================================
 * 
 * Wraps @radix-ui/react-dialog for full accessibility and unstyled logic.
 * 
 * Features:
 *   - Focus trapping (Tab stays inside the modal)
 *   - Escape key closes the modal
 *   - Backdrop click closes the modal (optional)
 *   - Background scrolling is disabled automatically
 *   - Fade-in/slide-up animations (defined in tailwind.config.ts)
 *   - Full dark mode support
 * 
 * Usage:
 *   <Modal open={isOpen} onOpenChange={setIsOpen}>
 *     <ModalContent>
 *       <ModalHeader>
 *         <ModalTitle>Create Incident</ModalTitle>
 *         <ModalDescription>Document the details of the new incident.</ModalDescription>
 *       </ModalHeader>
 *       <div>... form fields ...</div>
 *       <ModalFooter>
 *         <Button variant="ghost" onClick={() => setIsOpen(false)}>Cancel</Button>
 *         <Button onClick={submit}>Create</Button>
 *       </ModalFooter>
 *     </ModalContent>
 *   </Modal>
 */

import React, { forwardRef } from "react";
import * as DialogPrimitive from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import { cn } from "@/lib/utils";


// ============================================================================
// MODAL ROOT & TRIGGER
// ============================================================================

export const Modal = DialogPrimitive.Root;
export const ModalTrigger = DialogPrimitive.Trigger;
export const ModalClose = DialogPrimitive.Close;


// ============================================================================
// MODAL CONTENT (The actual overlay + dialog box)
// ============================================================================

export interface ModalContentProps extends React.ComponentPropsWithoutRef<typeof DialogPrimitive.Content> {
  /** Hide the default "X" close button in the top right */
  hideCloseButton?: boolean;
}

export const ModalContent = forwardRef<
  React.ElementRef<typeof DialogPrimitive.Content>,
  ModalContentProps
>(({ className, children, hideCloseButton, ...props }, ref) => (
  <DialogPrimitive.Portal>
    {/* Backdrop (Overlay) */}
    <DialogPrimitive.Overlay
      className={cn(
        "fixed inset-0 z-50 bg-slate-900/50 backdrop-blur-sm",
        "data-[state=open]:animate-fade-in",
        "dark:bg-slate-950/80"
      )}
    />
    
    {/* Dialog Content */}
    <DialogPrimitive.Content
      ref={ref}
      className={cn(
        "fixed left-[50%] top-[50%] z-50 grid w-full max-w-lg translate-x-[-50%] translate-y-[-50%] gap-4",
        "rounded-xl border border-slate-200 bg-white p-6 shadow-xl sm:rounded-xl",
        "dark:border-slate-800 dark:bg-slate-900",
        "data-[state=open]:animate-slide-in",
        className
      )}
      {...props}
    >
      {children}
      
      {/* Close button */}
      {!hideCloseButton && (
        <DialogPrimitive.Close
          className={cn(
            "absolute right-4 top-4 rounded-md p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-600",
            "focus:outline-none focus:ring-2 focus:ring-brand-500",
            "dark:text-slate-500 dark:hover:bg-slate-800 dark:hover:text-slate-300"
          )}
        >
          <X className="h-4 w-4" />
          <span className="sr-only">Close</span>
        </DialogPrimitive.Close>
      )}
    </DialogPrimitive.Content>
  </DialogPrimitive.Portal>
));
ModalContent.displayName = "ModalContent";


// ============================================================================
// LAYOUT PIECES
// ============================================================================

export const ModalHeader = ({
  className,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) => (
  <div
    className={cn("flex flex-col space-y-1.5 text-center sm:text-left", className)}
    {...props}
  />
);
ModalHeader.displayName = "ModalHeader";


export const ModalFooter = ({
  className,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) => (
  <div
    className={cn(
      "flex flex-col-reverse sm:flex-row sm:justify-end sm:space-x-2",
      className
    )}
    {...props}
  />
);
ModalFooter.displayName = "ModalFooter";


// ============================================================================
// TYPOGRAPHY
// ============================================================================

export const ModalTitle = forwardRef<
  React.ElementRef<typeof DialogPrimitive.Title>,
  React.ComponentPropsWithoutRef<typeof DialogPrimitive.Title>
>(({ className, ...props }, ref) => (
  <DialogPrimitive.Title
    ref={ref}
    className={cn(
      "text-lg font-semibold leading-none tracking-tight text-slate-900 dark:text-slate-100",
      className
    )}
    {...props}
  />
));
ModalTitle.displayName = "ModalTitle";


export const ModalDescription = forwardRef<
  React.ElementRef<typeof DialogPrimitive.Description>,
  React.ComponentPropsWithoutRef<typeof DialogPrimitive.Description>
>(({ className, ...props }, ref) => (
  <DialogPrimitive.Description
    ref={ref}
    className={cn("text-sm text-slate-500 dark:text-slate-400", className)}
    {...props}
  />
));
ModalDescription.displayName = "ModalDescription";

export interface SimpleModalProps {
  open?: boolean;
  isOpen?: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
}

export function SimpleModal({ open, isOpen, onClose, title, children }: SimpleModalProps) {
  const isCurrentlyOpen = open ?? isOpen ?? false;
  return (
    <Modal open={isCurrentlyOpen} onOpenChange={(v) => { if (!v) onClose(); }}>
      <ModalContent>
        <ModalHeader>
          <ModalTitle>{title}</ModalTitle>
        </ModalHeader>
        {children}
      </ModalContent>
    </Modal>
  );
}
