using System;
using System.Collections.Generic;
using System.Text;

namespace AccessSentry
{
    public static class SubjectHelper
    {
        public static string UserPrefix { get; set; } = "u::";
        public static string GroupPrefix { get; set; } = "g::";

        public static bool IsGroupSubject(string subject)
        {
            return subject.StartsWith(GroupPrefix);
        }

        public static bool IsUserSubject(string subject)
        {
            return subject.StartsWith(UserPrefix);
        }

        public static string StripSubjectPrefix(string subject)
        {
            return subject.Replace(UserPrefix, "").Replace(GroupPrefix, "");
        }

        public static string FormatGroupSubject(string subject)
        {
            if (IsGroupSubject(subject))
            {
                return subject;
            }

            if (IsUserSubject(subject))
            {
                throw new FormatException("Subject already marked as subject");
            }

            return $"{GroupPrefix}{subject.ToUpper()}";
        }

        public static string FormatUserSubject(string subject)
        {
            if (IsUserSubject(subject))
            {
                return subject;
            }

            if (IsGroupSubject(subject))
            {
                throw new FormatException("Subject already marked as group");
            }

            return $"{UserPrefix}{subject.ToUpper()}";
        }
    }
}
