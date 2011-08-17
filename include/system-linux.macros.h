#ifndef SYSTEM_LINUX_MACROS_H
#define SYSTEM_LINUX_MACROS_H

#define hsc_alignment(t) \
  printf("(%lu)", (unsigned long) offsetof (struct { char x__; t (y__); }, y__));
#define hsc_offsetof(s,f) \
  printf("(%lu)", (unsigned long) offsetof (s, f));
#define hsc_fsize(s,f) \
  printf("(%lu)", (unsigned long) sizeof (((s *) 0)->f));
#define hsc_skip(s,p,f) \
  printf("uncheckedSkip (%lu)", \
         (unsigned long) offsetof (s, f) - offsetof (s, p) \
                         - sizeof (((s *) 0)->p));
#define hsc_skipAndGet(s,p,f) \
  hsc_skip(s, p, f) \
  printf(">> get");
#define hsc_zero(s,p,f) \
  printf("zero (%lu)", \
         (unsigned long) offsetof (s, f) - offsetof (s, p) \
                         - sizeof (((s *) 0)->p));
#define hsc_zeroAndPut(s,p,f) \
  hsc_zero(s, p, f) \
  printf(">> put");

#endif /* SYSTEM_LINUX_MACROS_H */

