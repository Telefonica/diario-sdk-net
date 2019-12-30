using System;
using System.Diagnostics;

namespace DiarioSDKNet
{
    public class Tracer
    {
        #region Const

        private const string SOURCENAME = "BASESDKTRACE";
        private const string ERROR = "[ERROR] ";
        private static object locker = new object();

        #endregion Const

        #region PrivateMembers

        private static Tracer instance = null;
        private TraceSource tSource;

        #endregion PrivateMembers

        #region PublicProperties

        public static Tracer Instance
        {
            get
            {
                lock (locker)
                {
                    if (instance == null)
                        instance = new Tracer();

                    return instance;
                }
            }
        }

        #endregion PublicProperties

        #region Constructors

        private Tracer()
        {
            tSource = new TraceSource(SOURCENAME);
            Trace.AutoFlush = true;
        }

        #endregion Constructors

        #region PublicMethods

        public void TraceAndOutputError(string message)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(ERROR + message);
            Console.ResetColor();
            TraceError(message);
        }

        public void TraceError(string message)
        {
            tSource.TraceEvent(TraceEventType.Error, 0, message);
        }

        #endregion PublicMethods
    }
}

