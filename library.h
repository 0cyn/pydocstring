#pragma once

#include <string>
#include <utility>
#include <iostream>

#define assert(cond, where, what) if (!(cond)) { printf("%s: %s", where, what); abort(); }
#define assert_terminal(block) assert(block.terminal, __FUNCTION__, "Block must contain only text")
#define assert_nonterminal(block) assert(!block.terminal, __FUNCTION__, "Block cannot be terminal")
#define assert_kind(block, kind) assert(block.kind == kind, __FUNCTION__, "bad kind")
#define ret_stringify(member) case member: return #member ;

namespace DSParser {

    class EOFException : public std::exception {
    };
    class FormattingException : public std::exception {

    };

    std::string replace_first(const std::string& s, std::string const& toReplace, std::string const& replaceWith)
    {
        std::size_t pos = s.find(toReplace);
        if (pos == std::string::npos)
            return s;
        auto out = s;
        out.replace(pos, toReplace.length(), replaceWith);
        return out;
    }
    std::string replace_all(const std::string& s, const std::string& toReplace, const std::string& replaceWith) {
        std::string out = s;
        std::size_t pos = 0;
        while ((pos = out.find(toReplace, pos)) != std::string::npos) {
            out.replace(pos, toReplace.length(), replaceWith);
            pos += replaceWith.length();
        }
        return out;
    }

    class Reader {
        uint64_t m_cursor = 0;
        std::string m_string;
    public:
        struct ReaderFindCharPair { std::string out; char found; };
        struct ReaderFindStringPair { std::string out; std::string found; };
        uint64_t cursor() const { return m_cursor; };
        bool empty() { return m_string.empty(); }
        bool atEOF() { return m_cursor == m_string.size(); }
        void reset() { m_cursor = 0; }
        explicit Reader(std::string string) : m_string(std::move(string)) {}
        char PeekCursor()
        {
            if (m_cursor == m_string.size())
                throw EOFException();
            return m_string[m_cursor];
        }
        std::string PeekCursor(size_t cnt)
        {
            std::string out;
            for (size_t i = m_cursor; i < (m_cursor + cnt); i++)
            {
                if (i >= m_string.size())
                    throw EOFException();
                out.push_back(m_string[i]);
            }
            return out;
        }
        char PopCursorOne()
        {
            if (m_cursor == m_string.size())
                throw EOFException();
            return m_string[m_cursor++];
        }
        std::string PopTillEOF()
        {
            auto readableCount = (int64_t)(m_string.size() - m_cursor);
            if (readableCount <= 0)
                throw EOFException();
            std::string out;
            while (readableCount)
            {
                out.push_back(PopCursorOne());
                readableCount--;
            }
            m_cursor += out.size();
            return out;
        }
        std::string PopCountTillEOF(uint64_t requestedCount)
        {
            // "abcde"
            // cursor = 3, rest = "de"
            // request = 10, actual = 2, m_string.size() = 5
            auto readableCount = (int64_t)(m_string.size() - m_cursor);
            if (readableCount <= 0)
                throw EOFException();
            std::string out;
            uint64_t readCount = std::min((uint64_t)readableCount, requestedCount);
            while (readCount)
            {
                out.push_back(PopCursorOne());
                readCount--;
            }
            m_cursor += out.size();
            return out;
        }
        
        std::string ReadUntilExclude(char character)
        {
            std::string out;
            while (true)
            {
                if (PeekCursor() == character)
                    return out;

                out.push_back(PopCursorOne());
            }
        }
        std::string ReadUntilNotExclude(char character)
        {
            std::string out;
            while (true)
            {
                if (PeekCursor() != character)
                    return out;

                out.push_back(PopCursorOne());
            }
        }
        std::string ReadUntilExclude(const std::string& string)
        {
            std::string out;
            while (true)
            {
                if (PeekCursor(string.size()) == string)
                {
                    // We've advanced into the entire item at this point, so backtrack since this
                    //  isnt include
                    if (string.size() > 1)
                        m_cursor -= string.size();
                    return out;
                }

                out.push_back(PopCursorOne());
            }
        }
        ReaderFindCharPair ReadUntilOneOfExclude(std::vector<char> characters)
        {
            std::string out;
            while (true)
            {
                if (std::count(characters.begin(), characters.end(), PeekCursor()))
                    return {out, PeekCursor()};

                out.push_back(PopCursorOne());
            }
        }
        ReaderFindCharPair ReadUntilOneOfExcludeUntilEOF(std::vector<char> characters)
        {
            std::string out;
            while (true)
            {
                try {
                    if (std::count(characters.begin(), characters.end(), PeekCursor()))
                        return {out, PeekCursor()};

                    out.push_back(PopCursorOne());
                }
                catch (EOFException& ex)
                {
                    return {out, '\0'};
                }
            }
        }
        ReaderFindCharPair ReadUntilNotOneOfExclude(std::vector<char> characters)
        {
            std::string out;
            while (true)
            {
                if (!std::count(characters.begin(), characters.end(), PeekCursor()))
                    return {out, PeekCursor()};

                out.push_back(PopCursorOne());
            }
        }
        ReaderFindStringPair ReadUntilOneOfExclude(const std::vector<std::string>& characters)
        {
            std::string out;
            while (true)
            {
                for (const auto& item : characters)
                {
                    if (PeekCursor(item.size()) == item)
                    {
                        // We've advanced into the entire item at this point, so backtrack since this
                        //  isnt include
                        m_cursor -= item.size();
                        return {out, item};
                    }
                }

                out.push_back(PopCursorOne());
            }
        }
        ReaderFindStringPair ReadUntilOneOfExcludeUntilEOF(const std::vector<std::string>& characters)
        {
            std::string out;
            while (true)
            {
                try {
                    for (const auto& item : characters)
                    {
                        try {
                            if (PeekCursor(item.size()) == item)
                            {
                                // We've advanced into the entire item at this point, so backtrack since this
                                //  isnt include
                                m_cursor -= item.size();
                                return {out, item};
                            }
                        }
                        // If this fails, we are just not going to find the thing.
                        // But, we want to cleanly return the rest of the file anyways,
                        // so just letting the loop continue to run is the best way to do that without ugly
                        // cursor math.
                        catch (EOFException) {
                            continue;
                        }
                    }

                    out.push_back(PopCursorOne());
                }
                catch (EOFException)
                {
                    return {out, ""};
                }
            }
        }
        std::string ReadUntilInclude(char character)
        {
            std::string out;
            while (true)
            {
                out.push_back(PopCursorOne());
                if (out.back() == character)
                    return out;
            }
        }
        std::string ReadUntilIncludeUntilEOF(char character)
        {
            std::string out;
            while (true)
            {
                try {
                    out.push_back(PopCursorOne());
                    if (out.back() == character)
                        return out;
                }
                catch (EOFException& ex)
                {
                    return out;
                }
            }
        }
        std::string ReadUntilInclude(std::string string)
        {
            std::string out;
            while (true)
            {
                if (PeekCursor(string.size()) == string)
                {
                    out += PopCountTillEOF(string.size());
                    return out;
                }

                out.push_back(PopCursorOne());
            }
        }
        ReaderFindCharPair ReadUntilOneOfInclude(std::vector<char> characters)
        {
            std::string out;
            while (true)
            {
                out.push_back(PopCursorOne());
                if (std::count(characters.begin(), characters.end(), out.back()))
                    return {out, out.back()};
            }
        }
        ReaderFindStringPair ReadUntilOneOfInclude(const std::vector<std::string>& characters)
        {
            std::string out;
            while (true)
            {
                for (const auto& item : characters)
                {
                    if (PeekCursor(item.size()) == item)
                    {
                        out += PopCountTillEOF(item.size());
                        return {out, item};
                    }
                }

                out.push_back(PopCursorOne());
            }
        }
        std::string PopLineUntilEOF()
        {
            auto out =  ReadUntilIncludeUntilEOF('\n');
            return out;
        }
        std::vector<std::string> PopAllLines()
        {
            std::vector<std::string> out;
            while (!atEOF())
                out.push_back(PopLineUntilEOF());
            return out;
        }
        std::string PopWhitespace()
        {
            return ReadUntilNotOneOfExclude({'\n', '\t', ' '}).out;
        }
        std::string PopWhitespaceUntilEOF()
        {
            std::string out;
            auto ws = {'\n', '\t', ' '};
            while (!atEOF())
            {
                if (std::count(ws.begin(), ws.end(), PeekCursor()) > 0)
                    out.push_back(PopCursorOne());
                else
                    return out;
            }
            return out;
        }
        static bool StringIsAllWhitespace(const std::string& s)
        {
            if (s.empty())
                return true;
            return Reader(s).PopWhitespaceUntilEOF().size() == s.size();
        }
        static int WhitespaceCharacterLengthAtStart(const std::string& s)
        {
            return Reader(replace_all(s, "\t", "    ")).PopWhitespaceUntilEOF().size();
        }
    };
}

struct Block {
    enum Kind {
        DocstringRoot,
        //
        Paragraph,
        //
        Text,
        //
        Emphasis,
        Bold,
        Mono,
        InlineClass,
        InlineModule,
        InlineFunction,
        // params
        Param,
        ParamType,
        ParamName,
        ParamDesc,
        // ret
        ReturnBlock,
        ReturnType,
        ReturnDesc,
        // Notations
        Note,
        Warning,
        //
        CodeBlockDescription,
        CodeBlock
    } kind;
    static std::string KindToString(Kind k)
    {
        switch (k)
        {
            ret_stringify(DocstringRoot)
            ret_stringify(Paragraph)
            ret_stringify(Text)
            ret_stringify(Emphasis)
            ret_stringify(Bold)
            ret_stringify(Mono)
            ret_stringify(InlineClass)
            ret_stringify(InlineFunction)
            ret_stringify(InlineModule)
            ret_stringify(Param)
            ret_stringify(ParamType)
            ret_stringify(ParamName)
            ret_stringify(ParamDesc)
            ret_stringify(ReturnBlock)
            ret_stringify(ReturnType)
            ret_stringify(ReturnDesc)
            ret_stringify(Note)
            ret_stringify(Warning)
            ret_stringify(CodeBlockDescription)
            ret_stringify(CodeBlock)
        }
    }
    bool terminal;
    std::string terminalText;

    std::vector<Block> blocks;
    std::vector<Block*> VisitBlocks(Block* block = nullptr)
    {
        std::vector<Block*> visited;

        for (auto& sub : blocks)
        {
            visited.push_back(&sub);
            auto subCont = sub.VisitBlocks(&sub);
            visited.insert(visited.end(), subCont.begin(), subCont.end());
        }

        return visited;
    }
};

std::vector<std::string> blockStartTokens = {"``", "..", ":"};

class DocString {

    void NormalizeWhitespace(Block& block)
    {
        assert_terminal(block);
        if (!std::count(block.terminalText.begin(), block.terminalText.end(), '\n'))
            return;
        block.terminalText = DSParser::replace_all(block.terminalText, "    ", "\t");
        if (!DSParser::Reader::StringIsAllWhitespace(block.terminalText.substr(0, 1)))
            block.terminalText = "\n\t" + block.terminalText;

        DSParser::Reader r(block.terminalText);
        std::string line;
        while (DSParser::Reader::StringIsAllWhitespace(line) && !r.atEOF())
            line = r.PopLineUntilEOF();
        if (line.empty())
            return;
        auto normalWhiteSpace = DSParser::Reader(line).PopWhitespace();
        r.reset();
        block.terminalText = "";
        for (const auto& l : r.PopAllLines())
        {
            if (DSParser::Reader::StringIsAllWhitespace(line))
                block.terminalText += "\n";
            else
                block.terminalText += DSParser::replace_first(DSParser::replace_first(l, normalWhiteSpace, ""), "    ", "\t");
        }
    }
    void CreateParagraphs(Block& block)
    {
        DSParser::Reader r(block.terminalText);
        block.terminal = false;
        block.terminalText = "";

        Block curBlock{Block::Paragraph, true, ""};
        std::string line;
        for (const auto& line : r.PopAllLines())
        {
            if (DSParser::Reader::StringIsAllWhitespace(line))
            {
                if (!curBlock.terminalText.empty())
                    block.blocks.push_back(curBlock);
                curBlock = {Block::Paragraph, true, ""};
            }
            else
            {
                curBlock.terminalText += line;
            }
        }
        if (!curBlock.terminalText.empty())
            block.blocks.push_back(curBlock);
    }
    void CreateCodeBlocks(Block& block)
    {
        assert_kind(block, Block::DocstringRoot);
        assert_nonterminal(block);

        for (auto& subBlock : block.blocks)
        {
            if (!subBlock.terminal)
                continue;
            bool passesCondition = true;
            auto lines = DSParser::Reader(subBlock.terminalText).PopAllLines();
            std::string normalizedText;
            for (const auto& line : lines)
            {
                if (line.substr(0, 1) != "\t")
                {
                    passesCondition = false;
                    break;
                }
            }
            if (!passesCondition)
                continue;
            auto normalWhitespace = DSParser::Reader(lines[0]).PopWhitespaceUntilEOF();
            for (const auto& line : lines)
            {
                normalizedText += DSParser::replace_first(line, normalWhitespace, "");
            }
            subBlock.kind = Block::CodeBlock;
            subBlock.terminalText = normalizedText;
        }
    }
    void CreateNotesAndWarnings(Block& block)
    {
        assert_kind(block, Block::DocstringRoot);
        assert_nonterminal(block);

        for (auto& subBlock : block.blocks)
        {
            if (subBlock.kind != Block::Paragraph)
                continue;
            assert_terminal(subBlock);

            if (subBlock.terminalText.substr(0, 2) != "..")
            {
                continue;
            }

            DSParser::Reader br(subBlock.terminalText);
            auto ws = br.ReadUntilNotExclude('.');
            br.PopWhitespace();
            auto type = br.ReadUntilExclude(':');
            br.ReadUntilNotExclude(':');
            auto text = br.PopTillEOF();
            if (type == "note")
            {
                subBlock.kind = Block::Note;
                subBlock.terminalText = text;
            }
            else if (type == "warning" || type == "warn")
            {
                subBlock.kind = Block::Warning;
                subBlock.terminalText = text;
            }
        }
    }
    void CreateVariableItems(Block& block)
    {
        std::string amended;
        Block* lastBlock = nullptr;
        size_t lastLineStartSize = 0;
        Block returnBlock{Block::ReturnBlock, false, ""};
        for (const auto& line : DSParser::Reader(block.terminalText).PopAllLines())
        {
            if (line.substr(0, 1) == ":")
            {
                DSParser::Reader lr(line);

                lr.PopCursorOne();
                auto kind = lr.ReadUntilOneOfExclude({' ', ':'});
                if (kind.out == "param")
                {
                    std::string type;
                    std::string name;
                    while (true)
                    {
                        auto token = lr.ReadUntilOneOfExclude({' ', ':'});
                        if (token.found == ' ')
                            type += token.out;
                        else
                        {
                            name += token.out;
                            break;
                        }
                        lr.PopCursorOne();
                    }
                    lr.PopCursorOne();
                    std::cout << lr.cursor() << std::endl;
                    lastLineStartSize = lr.cursor() + 1;
                    Block newBlock{Block::Param, false, "", {
                        Block{Block::ParamName, true, name},
                        Block{Block::ParamType, true, type},
                        Block{Block::ParamDesc, true, lr.PopTillEOF()},
                    }};
                    block.blocks.push_back(newBlock);
                    lastBlock = &block.blocks.back().blocks[2];
                }
                else if (kind.out == "rtype")
                {
                    lr.ReadUntilInclude(':');
                    lr.PopWhitespace();
                    lastLineStartSize = lr.cursor();
                    returnBlock.blocks.push_back(Block{Block::ReturnType, true, lr.PopTillEOF()});
                    lastBlock = returnBlock.blocks.end().base();
                }
                else if (kind.out == "return")
                {
                    lr.ReadUntilInclude(':');
                    lr.PopWhitespace();
                    lastLineStartSize = lr.cursor();
                    returnBlock.blocks.push_back(Block{Block::ReturnDesc, true, lr.PopTillEOF()});
                    lastBlock = returnBlock.blocks.end().base();
                }
            }
            else
            {
                if (lastBlock)
                {
                    if (DSParser::Reader::WhitespaceCharacterLengthAtStart(line) == lastLineStartSize)
                    {
                        if (lastBlock->terminalText.back() == '\n')
                            lastBlock->terminalText = lastBlock->terminalText.substr(0, lastBlock->terminalText.size()-1);
                        auto text = line;
                        text = DSParser::replace_all(text, "\n", " ");
                        text = DSParser::replace_all(text, "\t", " ");
                        while (text.find("  ") != std::string::npos)
                            text = DSParser::replace_all(text, "  ", " ");
                        lastBlock->terminalText += text;
                        continue;
                    }
                }
                amended += line;
            }
        }
        block.terminalText = amended;
        if (!returnBlock.blocks.empty())
            block.blocks.push_back(returnBlock);
    }
    void ParseInternalFormatting(Block& rootBlock)
    {
        for (auto block : rootBlock.VisitBlocks())
        {
            if (!block->terminal)
                continue;
            if (block->kind == Block::CodeBlock)
                continue;

            auto br = DSParser::Reader(block->terminalText);
            block->terminal = false;

            Block textBlock{Block::Text, true, ""};
            while (true)
            {
                auto read = br.ReadUntilOneOfExcludeUntilEOF({":py:meth:", ":py:class:", ":py:func:",
                                                              ":py:mod:", ":func:", ":meth:", ":class:", ":mod:", "``", "`"});
                textBlock.terminalText += read.out;
                block->blocks.push_back(textBlock);
                if (read.found.empty())
                    break;
                textBlock = {Block::Text, true, ""};
                br.PopCountTillEOF(read.found.size());
                if (read.found == ":class:" || read.found == ":py:class:")
                {
                    if (br.PeekCursor() != '`')
                        throw DSParser::FormattingException();

                    br.PopCursorOne();
                    auto text = br.ReadUntilExclude('`');
                    br.PopCursorOne();
                    block->blocks.push_back({Block::InlineClass, true, text});
                }
                else if (read.found == ":mod:" || read.found == ":py:mod:")
                {
                    if (br.PeekCursor() != '`')
                        throw DSParser::FormattingException();

                    br.PopCursorOne();
                    auto text = br.ReadUntilExclude('`');
                    br.PopCursorOne();
                    block->blocks.push_back({Block::InlineModule, true, text});
                }
                else if (read.found == ":py:meth:" || read.found == ":py:func:"
                        || read.found == ":meth:" || read.found == ":func:")
                {
                    if (br.PeekCursor() != '`')
                        throw DSParser::FormattingException();

                    br.PopCursorOne();
                    auto text = br.ReadUntilExclude('`');
                    br.PopCursorOne();
                    block->blocks.push_back({Block::InlineFunction, true, text});
                }
                else if (read.found == "``")
                {
                    auto text = br.ReadUntilExclude("``");
                    block->blocks.push_back({Block::Mono, true, text});
                    br.PopCountTillEOF(2);
                }
                else if (read.found == "`")
                {
                    auto text = br.ReadUntilExclude("`");
                    block->blocks.push_back({Block::Emphasis, true, text});
                    br.PopCursorOne();
                }
            }
        }
    }
public:
    Block allRoot;
    std::vector<Block> params;
    std::vector<Block> ret;

    explicit DocString(const std::string& docstring)
    {
        DSParser::Reader docReader(docstring);
        Block root{Block::DocstringRoot, true, docstring};

        NormalizeWhitespace(root);
        CreateVariableItems(root);
        CreateParagraphs(root);
        CreateCodeBlocks(root);
        CreateNotesAndWarnings(root);
        ParseInternalFormatting(root);

        for (const auto& block : root.VisitBlocks())
        {
            if (block->kind == Block::Param)
                params.emplace_back(*block);
            else if (block->kind == Block::ReturnBlock)
                ret.emplace_back(*block);
        }

        allRoot = root;
    }
    static std::string Dump(const Block& block, uint64_t ind = 0)
    {
        std::string s;
        std::string indent;
        uint64_t indentCount = ind;
        while (indentCount > 0)
        {
            indent += "\t";
            indentCount--;
        }
        s += indent + Block::KindToString(block.kind) += "\n";
        if (block.terminal)
        {
            for (const auto& line : DSParser::Reader(block.terminalText).PopAllLines())
            {
                auto outLine = indent + "  " + line;
                if (outLine.back() != '\n')
                    outLine.push_back('\n');
                s += outLine;
            }
        }
        else
        {
            for (const auto& subBlock : block.blocks)
            {
                s += Dump(subBlock, ind + 1);
            }
        }

        return s;
    }
};
