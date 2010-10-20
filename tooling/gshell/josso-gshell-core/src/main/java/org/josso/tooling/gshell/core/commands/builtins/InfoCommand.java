/*
 * JOSSO: Java Open Single Sign-On
 *
 * Copyright 2004-2009, Atricore, Inc.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 *
 */

package org.josso.tooling.gshell.core.commands.builtins;

import org.apache.geronimo.gshell.command.annotation.CommandComponent;
import org.apache.geronimo.gshell.command.annotation.Requirement;
import org.apache.geronimo.gshell.branding.Branding;
import org.apache.geronimo.gshell.ansi.Renderer;
import org.apache.geronimo.gshell.ansi.Code;
import org.codehaus.plexus.util.StringUtils;
import org.josso.tooling.gshell.core.support.JOSSOCommandSupport;

import java.text.NumberFormat;
import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.util.Locale;
import java.util.Map;
import java.util.HashMap;
import java.lang.management.*;
import java.lang.reflect.Method;

/**
 * Display environmental informations
 */
@CommandComponent(id="gshell-builtins:info", description="Show system informations")
public class InfoCommand
    extends JOSSOCommandSupport
{

    @Requirement
    private Branding branding;

    private Renderer renderer = new Renderer();
    private NumberFormat fmtI = new DecimalFormat("###,###", new DecimalFormatSymbols(Locale.ENGLISH));
    private NumberFormat fmtD = new DecimalFormat("###,##0.000", new DecimalFormatSymbols(Locale.ENGLISH));

    public InfoCommand(Branding branding) {
        this.branding = branding;
    }

    @Override
    protected JOSSOCommandSupport createCommand() throws Exception {
        return new InfoCommand(branding);
    }

    @Override
    protected Object doExecute() throws Exception {
        int maxNameLen;
        String name;
        Map<String, String> props = new HashMap<String, String>();

        RuntimeMXBean runtime = ManagementFactory.getRuntimeMXBean();
        OperatingSystemMXBean os = ManagementFactory.getOperatingSystemMXBean();
        ThreadMXBean threads = ManagementFactory.getThreadMXBean();
        MemoryMXBean mem = ManagementFactory.getMemoryMXBean();
        ClassLoadingMXBean    cl = ManagementFactory.getClassLoadingMXBean();

        //
        // print ServiceMix informations
        //
        maxNameLen = 25;
        io.out.println("JOSSO");
        printValue("JOSSO version", maxNameLen, branding.getVersion());
        io.out.println();

        io.out.println("JVM");
        printValue("Java Virtual Machine", maxNameLen, runtime.getVmName() + " version " + runtime.getVmVersion());
        printValue("Vendor", maxNameLen, runtime.getVmVendor());
        printValue("Uptime", maxNameLen, printDuration(runtime.getUptime()));
        try {
            printValue("Process CPU time", maxNameLen, printDuration(getSunOsValueAsLong(os, "getProcessCpuTime") / 1000000));
        } catch (Throwable t) {}
        printValue("Total compile time", maxNameLen, printDuration(ManagementFactory.getCompilationMXBean().getTotalCompilationTime()));

        io.out.println("Threads");
        printValue("Live threads", maxNameLen, Integer.toString(threads.getThreadCount()));
        printValue("Daemon threads", maxNameLen, Integer.toString(threads.getDaemonThreadCount()));
        printValue("Peak", maxNameLen, Integer.toString(threads.getPeakThreadCount()));
        printValue("Total started", maxNameLen, Long.toString(threads.getTotalStartedThreadCount()));

        io.out.println("Memory");
        printValue("Current heap size", maxNameLen, printSizeInKb(mem.getHeapMemoryUsage().getUsed()));
        printValue("Maximum heap size", maxNameLen, printSizeInKb(mem.getHeapMemoryUsage().getMax()));
        printValue("Committed heap size", maxNameLen, printSizeInKb(mem.getHeapMemoryUsage().getCommitted()));
        printValue("Pending objects", maxNameLen, Integer.toString(mem.getObjectPendingFinalizationCount()));
        for (GarbageCollectorMXBean gc : ManagementFactory.getGarbageCollectorMXBeans()) {
            String val = "Name = '" + gc.getName() + "', Collections = " + gc.getCollectionCount() + ", Time = " + printDuration(gc.getCollectionTime());
            printValue("Garbage collector", maxNameLen, val);
        }

        io.out.println("Classes");
        printValue("Current classes loaded", maxNameLen, printLong(cl.getLoadedClassCount()));
        printValue("Total classes loaded", maxNameLen, printLong(cl.getTotalLoadedClassCount()));
        printValue("Total classes unloaded", maxNameLen, printLong(cl.getUnloadedClassCount()));

        io.out.println("Operating system");
        printValue("Name", maxNameLen, os.getName() + " version " + os.getVersion());
        printValue("Architecture", maxNameLen, os.getArch());
        printValue("Processors", maxNameLen, Integer.toString(os.getAvailableProcessors()));
        try {
            printValue("Total physical memory", maxNameLen, printSizeInKb(getSunOsValueAsLong(os, "getTotalPhysicalMemorySize")));
            printValue("Free physical memory", maxNameLen, printSizeInKb(getSunOsValueAsLong(os, "getFreePhysicalMemorySize")));
            printValue("Committed virtual memory", maxNameLen, printSizeInKb(getSunOsValueAsLong(os, "getCommittedVirtualMemorySize")));
            printValue("Total swap space", maxNameLen, printSizeInKb(getSunOsValueAsLong(os, "getTotalSwapSpaceSize")));
            printValue("Free swap space", maxNameLen, printSizeInKb(getSunOsValueAsLong(os, "getFreeSwapSpaceSize")));
        } catch (Throwable t) {}

        return null;
    }

    private long getSunOsValueAsLong(OperatingSystemMXBean os, String name) throws Exception {
        Method mth = os.getClass().getMethod(name);
        return (Long) mth.invoke(os);
    }

    private String printLong(long i) {
        return fmtI.format(i);
    }

    private String printSizeInKb(double size) {
        return fmtI.format((long) (size / 1024)) + " kbytes";
    }

    private String printDuration(double uptime) {
        uptime /= 1000;
        if (uptime < 60) {
            return fmtD.format(uptime) + " seconds";
        }
        uptime /= 60;
        if (uptime < 60) {
            long minutes = (long) uptime;
            String s = fmtI.format(minutes) + (minutes > 1 ? " minutes" : " minute");
            return s;
        }
        uptime /= 60;
        if (uptime < 24) {
            long hours = (long) uptime;
            long minutes = (long) ((uptime - hours) * 60);
            String s = fmtI.format(hours) + (hours > 1 ? " hours" : " hour");
            if (minutes != 0) {
                s += " " + fmtI.format(minutes) + (minutes > 1 ? " minutes" : "minute");
            }
            return s;
        }
        uptime /= 24;
        long days = (long) uptime;
        long hours = (long) ((uptime - days) * 60);
        String s = fmtI.format(days) + (days > 1 ? " days" : " day");
        if (hours != 0) {
            s += " " + fmtI.format(hours) + (hours > 1 ? " hours" : "hour");
        }
        return s;
    }

    void printSysValue(String prop, int pad) {
        printValue(prop, pad, System.getProperty(prop));
    }

    void printValue(String name, int pad, String value) {
        io.out.println("  " + renderer.render(Renderer.encode(StringUtils.rightPad(name, pad), Code.BOLD)) + "   " + value);
    }

}
