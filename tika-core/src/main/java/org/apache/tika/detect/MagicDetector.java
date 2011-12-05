/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.tika.detect;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.tika.metadata.Metadata;
import org.apache.tika.mime.MediaType;

/**
 * Content type detection based on magic bytes, i.e. type-specific patterns
 * near the beginning of the document input stream.
 *
 * @since Apache Tika 0.3
 */
public class MagicDetector implements Detector {

    /**
     * The matching media type. Returned by the
     * {@link #detect(InputStream, Metadata)} method if a match is found.
     */
    private final MediaType type;

    /**
     * Length of the comparison window. All the byte arrays here are this long.
     */
    private final int length;

    /**
     * PSM: Add pattern type (regex or String)
     */
    private final String patternType;
    
    /**
     * The magic match pattern. If this byte pattern is equal to the
     * possibly bit-masked bytes from the input stream, then the type
     * detection succeeds and the configured {@link #type} is returned.
     */
    private final byte[] pattern;

    /**
     * Bit mask that is applied to the source bytes before pattern matching.
     */
    private final byte[] mask;

    /**
     * First offset (inclusive) of the comparison window within the
     * document input stream. Greater than or equal to zero.
     */
    private final int offsetRangeBegin;

    /**
     * Last offset (inclusive) of the comparison window within the document
     * input stream. Greater than or equal to the
     * {@link #offsetRangeBegin first offset}.
     * <p>
     * Note that this is <em>not</em> the offset of the last byte read from
     * the document stream. Instead, the last window of bytes to be compared
     * starts at this offset.
     */
    private final int offsetRangeEnd;
    
    private final String asString;

    /**
     * Creates a detector for input documents that have the exact given byte
     * pattern at the beginning of the document stream.
     *
     * @param type matching media type
     * @param pattern magic match pattern
     */
    public MagicDetector(MediaType type, byte[] pattern) {
        this(type, pattern, 0);
    }

    /**
     * Creates a detector for input documents that have the exact given byte
     * pattern at the given offset of the document stream.
     *
     * @param type matching media type
     * @param pattern magic match pattern
     * @param offset offset of the pattern match
     */
    public MagicDetector(MediaType type, byte[] pattern, int offset) {
        this(type, pattern, null, offset, offset);
    }

    /**
     * Creates a detector capable of handling regular expression pattern types
     * 
     * @param type
     * @param patternType
     * @param pattern
     * @param mask
     * @param offsetRangeBegin
     * @param offsetRangeEnd
     */
    public MagicDetector(
    		MediaType type, String patternType, byte[] pattern, byte[] mask,
            int offsetRangeBegin, int offsetRangeEnd) {
    	if (type == null) {
            throw new IllegalArgumentException("Matching media type is null");
        } else if (pattern == null) {
            throw new IllegalArgumentException("Magic match pattern is null");
        } else if (offsetRangeBegin < 0
                || offsetRangeEnd < offsetRangeBegin) {
            throw new IllegalArgumentException(
                    "Invalid offset range: ["
                    + offsetRangeBegin + "," + offsetRangeEnd + "]");
        }

        this.type = type;

        // Length of regular expression does not reflect the buffer byte length. 
        // Simple solution to handle with an 8K buffer, but this currently causes test failures
//        if (patternType.equals("regex")){
//        	this.length = 8*1024; // 8K buffer
//        } else {
        	this.length = Math.max(pattern.length, mask != null ? mask.length : 0);
//        }

        this.mask = new byte[length];
        this.pattern = new byte[length];
        this.patternType = patternType;

        for (int i = 0; i < length; i++) {
            if (mask != null && i < mask.length) {
                this.mask[i] = mask[i];
            } else {
                this.mask[i] = -1;
            }

            if (i < pattern.length) {
                this.pattern[i] = (byte) (pattern[i] & this.mask[i]);
            } else {
                this.pattern[i] = 0;
            }
        }

        this.offsetRangeBegin = offsetRangeBegin;
        this.offsetRangeEnd = offsetRangeEnd;
        
        // Build the string representation. Needs to be unique, as
        //  these get compared. Compute now as may get compared a lot!
        this.asString = "Magic Detection for " + type.toString() +
          " looking for " + pattern.length + 
          " bytes = " + this.pattern + 
          " mask = " + this.mask;
    	
    }
    
    /**
     * Creates a detector for input documents that meet the specified
     * magic match.
     */
    public MagicDetector(
            MediaType type, byte[] pattern, byte[] mask,
            int offsetRangeBegin, int offsetRangeEnd) {
        if (type == null) {
            throw new IllegalArgumentException("Matching media type is null");
        } else if (pattern == null) {
            throw new IllegalArgumentException("Magic match pattern is null");
        } else if (offsetRangeBegin < 0
                || offsetRangeEnd < offsetRangeBegin) {
            throw new IllegalArgumentException(
                    "Invalid offset range: ["
                    + offsetRangeBegin + "," + offsetRangeEnd + "]");
        }

        this.type = type;

        this.length = Math.max(pattern.length, mask != null ? mask.length : 0);

        this.mask = new byte[length];
        this.pattern = new byte[length];
        this.patternType = "";

        for (int i = 0; i < length; i++) {
            if (mask != null && i < mask.length) {
                this.mask[i] = mask[i];
            } else {
                this.mask[i] = -1;
            }

            if (i < pattern.length) {
                this.pattern[i] = (byte) (pattern[i] & this.mask[i]);
            } else {
                this.pattern[i] = 0;
            }
        }

        this.offsetRangeBegin = offsetRangeBegin;
        this.offsetRangeEnd = offsetRangeEnd;
        
        // Build the string representation. Needs to be unique, as
        //  these get compared. Compute now as may get compared a lot!
        this.asString = "Magic Detection for " + type.toString() +
          " looking for " + pattern.length + 
          " bytes = " + this.pattern + 
          " mask = " + this.mask;
    }

    /**
     * 
     * @param input document input stream, or <code>null</code>
     * @param metadata ignored
     */
    public MediaType detect(InputStream input, Metadata metadata)
            throws IOException {
        if (input == null) {
            return MediaType.OCTET_STREAM;
        }

        input.mark(offsetRangeEnd + length);
        try {
            int offset = 0;

            // Skip bytes at the beginning, using skip() or read()
            while (offset < offsetRangeBegin) {
                long n = input.skip(offsetRangeBegin - offset);
                if (n > 0) {
                    offset += n;
                } else if (input.read() != -1) {
                    offset += 1;
                } else {
                    return MediaType.OCTET_STREAM;
                }
            }

            // Fill in the comparison window
            byte[] buffer =
                new byte[length + (offsetRangeEnd - offsetRangeBegin)];
            int n = input.read(buffer);
            if (n > 0) {
                offset += n;
            }
            while (n != -1 && offset < offsetRangeEnd + length) {
                int bufferOffset = offset - offsetRangeBegin;
                n = input.read(
                        buffer, bufferOffset, buffer.length - bufferOffset);
            }
            if (offset < offsetRangeBegin + length) {
                return MediaType.OCTET_STREAM;
            }
                    
            // PSM: Introduce matching using Regular Expressions
            if( this.patternType.equals("regex") ) {
//            	System.out.println("Matching on regular expression: "+new String(this.pattern));
            	Pattern p = Pattern.compile(new String(this.pattern));

            	ByteBuffer bb = ByteBuffer.wrap(buffer);
            	CharBuffer result = Charset.forName("ISO-8859-1").decode(bb);
            	Matcher m = p.matcher(result);
            	//Matcher m = p.matcher(new String(buffer));
            	boolean match = false;
            	for (int i=0; i<= offsetRangeEnd - offsetRangeBegin; i++){
//            		System.out.println("Buffer["+i+"]: "+(new String(buffer)).substring(i, i+length));
            		
            		m.region(i, length+i);
            		match = m.lookingAt();	// match regular expression from start of region
            	}
            	if(match){
            		return type;
            	}
            } else {
//            	System.out.println("Matching using non-regex ("+new String(this.pattern)+")");
                // Loop until we've covered the entire offset range
	            for (int i = 0; i <= offsetRangeEnd - offsetRangeBegin; i++) {
	                boolean match = true;
	                for (int j = 0; match && j < length; j++) {
	                    match = (buffer[i + j] & mask[j]) == pattern[j];
	                }
	                if (match) {
	                    return type;
	                }
	            }
            }

            return MediaType.OCTET_STREAM;
        } finally {
            input.reset();
        }
    }

    /**
     * Returns a string representation of the Detection Rule.
     * Should sort nicely by type and details, as we sometimes
     *  compare these.
     */
    public String toString() {
       return asString;
    }
}
